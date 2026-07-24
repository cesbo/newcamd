use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::crypto::{decrypt_message, derive_login_key, encrypt_message, md5_crypt};
use crate::error::{NewcamdError, Result};
use crate::protocol::msg;
use crate::protocol::{
    CWS_NETMSGSIZE, HEADER_SIZE_525, LOGIN_INIT_SEQ_LEN, NewcamdPacket, encode_payload,
    parse_decrypted_525, patch_payload_len,
};

#[derive(Debug, Clone)]
pub struct NewcamdConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub des_key_14: [u8; 14],
    pub caid: u16,
    pub provider: u32,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for NewcamdConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 15000,
            username: String::new(),
            password: String::new(),
            des_key_14: [0_u8; 14],
            caid: 0,
            provider: 0,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RawRequest {
    pub sid: u16,
    pub caid: u16,
    pub provider: u32,
}

#[derive(Debug, Clone)]
pub struct EcmRequest {
    pub sid: u16,
    pub caid: u16,
    pub provider: u32,
    pub section: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EcmResponse {
    pub found: bool,
    pub cw: [u8; 16],
    pub packet: NewcamdPacket,
}

#[derive(Debug, Clone)]
pub struct CardData {
    pub caid: u16,
    pub provider_count: usize,
    pub raw_payload: Vec<u8>,
}

pub struct NewcamdClient {
    stream: TcpStream,
    read_timeout: Duration,
    msg_id: u16,
    session_key: [u8; 16],
    default_caid: u16,
    default_provider: u32,
    pub card_data: CardData,
}

impl NewcamdClient {
    pub async fn connect(config: NewcamdConfig) -> Result<Self> {
        if config.username.is_empty() || config.password.is_empty() {
            return Err(NewcamdError::InvalidData(
                "username and password must not be empty".to_string(),
            ));
        }

        let endpoint = format!("{}:{}", config.host, config.port);
        let configured_caid = config.caid;
        let configured_provider = config.provider;
        let mut stream = timeout(config.connect_timeout, TcpStream::connect(endpoint))
            .await
            .map_err(|_| NewcamdError::Protocol("connect timeout"))??;

        let mut keymod = [0_u8; LOGIN_INIT_SEQ_LEN];
        timeout(config.read_timeout, stream.read_exact(&mut keymod))
            .await
            .map_err(|_| NewcamdError::Protocol("timeout while reading server init sequence"))??;

        let login_key = derive_login_key(&config.des_key_14, &keymod)?;
        let password_crypt = md5_crypt(&config.password, "abcdefgh");

        let mut login_data = Vec::with_capacity(config.username.len() + password_crypt.len() + 2);
        login_data.extend_from_slice(config.username.as_bytes());
        login_data.push(0);
        login_data.extend_from_slice(password_crypt.as_bytes());
        login_data.push(0);

        let login_payload = encode_payload(msg::MSG_CLIENT_2_SERVER_LOGIN, &login_data);
        send_network_message(&mut stream, None, &login_key, &login_payload, 0, 0, 0).await?;

        let login_answer = read_network_message(&mut stream, &login_key, config.read_timeout).await?;
        let mut msg_id = login_answer.header.msg_id;

        if login_answer.command == msg::MSG_CLIENT_2_SERVER_LOGIN_NAK {
            return Err(NewcamdError::AuthenticationFailed);
        }
        if login_answer.command != msg::MSG_CLIENT_2_SERVER_LOGIN_ACK {
            return Err(NewcamdError::Protocol("expected LOGIN_ACK packet"));
        }

        let session_key = derive_login_key(&config.des_key_14, password_crypt.as_bytes())?;
        let card_data_req = encode_payload(msg::MSG_CARD_DATA_REQ, &[]);
        send_network_message(
            &mut stream,
            Some(&mut msg_id),
            &session_key,
            &card_data_req,
            0,
            0,
            0,
        )
        .await?;

        let card_data_answer = read_network_message(&mut stream, &session_key, config.read_timeout).await?;
        if card_data_answer.command != msg::MSG_CARD_DATA {
            return Err(NewcamdError::Protocol("expected CARD_DATA packet"));
        }

        let caid = card_data_answer
            .data
            .get(3)
            .zip(card_data_answer.data.get(4))
            .map(|(hi, lo)| u16::from_be_bytes([*hi, *lo]))
            .ok_or(NewcamdError::Protocol("invalid CARD_DATA payload"))?;

        let provider_count = card_data_answer.data.get(14).copied().unwrap_or(0) as usize;
        let default_caid = if configured_caid == 0 { caid } else { configured_caid };
        let default_provider = configured_provider;

        Ok(Self {
            stream,
            read_timeout: config.read_timeout,
            msg_id,
            session_key,
            default_caid,
            default_provider,
            card_data: CardData {
                caid,
                provider_count,
                raw_payload: card_data_answer.data,
            },
        })
    }

    pub fn default_caid(&self) -> u16 {
        self.default_caid
    }

    pub fn default_provider(&self) -> u32 {
        self.default_provider
    }

    pub async fn send_raw(&mut self, command: u8, data: &[u8], req: RawRequest) -> Result<NewcamdPacket> {
        let payload = encode_payload(command, data);
        let caid = self.resolve_caid(req.caid);
        let provider = self.resolve_provider(req.provider);
        send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &payload,
            req.sid,
            caid,
            provider,
        )
        .await?;

        self.read_next_non_keepalive().await
    }

    pub async fn send_ecm(&mut self, req: &EcmRequest) -> Result<EcmResponse> {
        if req.section.len() < 3 {
            return Err(NewcamdError::InvalidData(
                "ECM section must include at least 3 bytes".to_string(),
            ));
        }

        let mut payload = req.section.clone();
        patch_payload_len(&mut payload);
        let caid = self.resolve_caid(req.caid);
        let provider = self.resolve_provider(req.provider);

        send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &payload,
            req.sid,
            caid,
            provider,
        )
        .await?;

        let sent_msg_id = self.msg_id;

        loop {
            let packet = self.read_next_non_keepalive().await?;
            let is_ecm_response = packet.header.msg_id == sent_msg_id
                || matches!(packet.command, 0x80 | 0x81);
            if !is_ecm_response {
                continue;
            }

            let mut cw = [0_u8; 16];
            if packet.data.is_empty() {
                return Ok(EcmResponse {
                    found: false,
                    cw,
                    packet,
                });
            }

            if packet.data.len() < 16 {
                return Err(NewcamdError::Protocol("ECM response payload is shorter than 16-byte CW"));
            }

            cw.copy_from_slice(&packet.data[..16]);
            return Ok(EcmResponse {
                found: true,
                cw,
                packet,
            });
        }
    }

    pub async fn send_emm(
        &mut self,
        section: &[u8],
        sid: u16,
        caid: u16,
        provider: u32,
    ) -> Result<Option<NewcamdPacket>> {
        if section.len() < 3 {
            return Err(NewcamdError::InvalidData(
                "EMM section must include at least 3 bytes".to_string(),
            ));
        }

        let mut payload = section.to_vec();
        patch_payload_len(&mut payload);
        let caid = self.resolve_caid(caid);
        let provider = self.resolve_provider(provider);

        send_network_message(
            &mut self.stream,
            Some(&mut self.msg_id),
            &self.session_key,
            &payload,
            sid,
            caid,
            provider,
        )
        .await?;

        let packet = self.read_next_non_keepalive().await?;
        if (0x82..0x90).contains(&packet.command) {
            return Ok(Some(packet));
        }

        Ok(None)
    }

    fn resolve_caid(&self, request_caid: u16) -> u16 {
        if request_caid == 0 {
            self.default_caid
        } else {
            request_caid
        }
    }

    fn resolve_provider(&self, request_provider: u32) -> u32 {
        if request_provider == 0 {
            self.default_provider
        } else {
            request_provider
        }
    }

    async fn read_next_non_keepalive(&mut self) -> Result<NewcamdPacket> {
        loop {
            let packet = read_network_message(&mut self.stream, &self.session_key, self.read_timeout).await?;
            if packet.command == msg::MSG_KEEPALIVE {
                continue;
            }
            return Ok(packet);
        }
    }
}

async fn send_network_message(
    stream: &mut TcpStream,
    msg_id: Option<&mut u16>,
    des_key: &[u8; 16],
    payload: &[u8],
    sid: u16,
    caid: u16,
    provider: u32,
) -> Result<()> {
    if payload.len() < 3 {
        return Err(NewcamdError::Protocol("payload must be at least 3 bytes"));
    }

    let mut netbuf = Vec::with_capacity(CWS_NETMSGSIZE);
    netbuf.resize(HEADER_SIZE_525, 0);
    netbuf.extend_from_slice(payload);

    let current_msg_id = if let Some(counter) = msg_id {
        *counter = counter.wrapping_add(1);
        *counter
    } else {
        0
    };

    netbuf[2..4].copy_from_slice(&current_msg_id.to_be_bytes());
    netbuf[4..6].copy_from_slice(&sid.to_be_bytes());
    netbuf[6..8].copy_from_slice(&caid.to_be_bytes());
    netbuf[8] = ((provider >> 16) & 0xFF) as u8;
    netbuf[9] = ((provider >> 8) & 0xFF) as u8;
    netbuf[10] = (provider & 0xFF) as u8;

    let mut to_encrypt = netbuf;
    let plain_len = to_encrypt.len();
    let wire_len = plain_len - 2;
    to_encrypt[0] = ((wire_len >> 8) & 0xFF) as u8;
    to_encrypt[1] = (wire_len & 0xFF) as u8;

    encrypt_message(&mut to_encrypt, des_key)?;

    let encrypted_wire_len = to_encrypt.len() - 2;
    to_encrypt[0] = ((encrypted_wire_len >> 8) & 0xFF) as u8;
    to_encrypt[1] = (encrypted_wire_len & 0xFF) as u8;

    stream.write_all(&to_encrypt).await?;

    Ok(())
}

async fn read_network_message(
    stream: &mut TcpStream,
    des_key: &[u8; 16],
    read_timeout: Duration,
) -> Result<NewcamdPacket> {
    let mut len_bytes = [0_u8; 2];
    timeout(read_timeout, stream.read_exact(&mut len_bytes))
        .await
        .map_err(|_| NewcamdError::Protocol("timeout while reading packet length"))??;

    let frame_len = u16::from_be_bytes(len_bytes) as usize;
    if frame_len + 2 > CWS_NETMSGSIZE {
        return Err(NewcamdError::Protocol("received frame is larger than CWS_NETMSGSIZE"));
    }

    let mut encrypted = vec![0_u8; frame_len + 2];
    encrypted[0] = len_bytes[0];
    encrypted[1] = len_bytes[1];

    timeout(read_timeout, stream.read_exact(&mut encrypted[2..]))
        .await
        .map_err(|_| NewcamdError::Protocol("timeout while reading packet body"))??;

    let plain_len = decrypt_message(&mut encrypted, des_key)?;
    parse_decrypted_525(&encrypted[..plain_len])
        .ok_or(NewcamdError::Protocol("failed to parse decrypted newcamd525 packet"))
}
