use std::env;
use std::time::Duration;

use newcamd_lib::{EcmRequest, NewcamdClient, NewcamdConfig};

struct CliArgs {
    config: NewcamdConfig,
    sid: u16,
    ecm_section: Option<Vec<u8>>,
    emm_section: Option<Vec<u8>>,
}

fn usage(program: &str) -> String {
    format!(
        "Usage:\n  {program} --user <username> --pass <password> --des-key <28_hex_chars> [--host <host>] [--port <port>] [--caid <u16|0xHEX>] [--provider <u32|0xHEX>] [--sid <u16|0xHEX>] [--ecm <hex_bytes>] [--emm <hex_bytes>]\n\nExamples:\n  {program} --user test --pass test123 --des-key 0102030405060708091011121314 --caid 0x09BD --provider 0x000000 --sid 0x0001 --ecm 803000000000\n  {program} --user test --pass test123 --des-key 0102030405060708091011121314 --caid 0x09BD --provider 0x000000 --sid 0x0001 --emm 820000000000"
    )
}

fn parse_u16_arg(raw: &str, name: &str) -> Result<u16, String> {
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).map_err(|_| format!("invalid {name} value '{raw}'"))?
    } else {
        raw.parse::<u16>()
            .map_err(|_| format!("invalid {name} value '{raw}'"))?
    };

    Ok(parsed)
}

fn parse_u32_arg(raw: &str, name: &str) -> Result<u32, String> {
    let parsed = if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid {name} value '{raw}'"))?
    } else {
        raw.parse::<u32>()
            .map_err(|_| format!("invalid {name} value '{raw}'"))?
    };

    Ok(parsed)
}

fn parse_hex_bytes(raw: &str, name: &str) -> Result<Vec<u8>, String> {
    let compact: String = raw
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ':' && *ch != ',')
        .collect();

    if compact.is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    if compact.len() % 2 != 0 {
        return Err(format!("{name} must contain an even number of hex characters"));
    }

    let mut out = Vec::with_capacity(compact.len() / 2);
    let mut index = 0;
    while index < compact.len() {
        let next = index + 2;
        let chunk = &compact[index..next];
        let byte = u8::from_str_radix(chunk, 16)
            .map_err(|_| format!("invalid hex byte '{chunk}' in {name}"))?;
        out.push(byte);
        index = next;
    }

    Ok(out)
}

fn parse_cli_args() -> Result<CliArgs, String> {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "newcamd_client".to_string());

    let mut host = "127.0.0.1".to_string();
    let mut port: u16 = 15000;
    let mut caid: u16 = 0;
    let mut provider: u32 = 0;
    let mut sid: u16 = 1;
    let mut username = String::new();
    let mut password = String::new();
    let mut des_key_hex = String::new();
    let mut ecm_section: Option<Vec<u8>> = None;
    let mut emm_section: Option<Vec<u8>> = None;

    let mut rest = args.peekable();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--host" => {
                host = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --host\n{}", usage(&program)))?;
            }
            "--port" => {
                let raw = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --port\n{}", usage(&program)))?;
                port = parse_u16_arg(&raw, "--port")
                    .map_err(|err| format!("{err}\n{}", usage(&program)))?;
            }
            "--caid" => {
                let raw = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --caid\n{}", usage(&program)))?;
                caid = parse_u16_arg(&raw, "--caid")
                    .map_err(|err| format!("{err}\n{}", usage(&program)))?;
            }
            "--provider" => {
                let raw = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --provider\n{}", usage(&program)))?;
                provider = parse_u32_arg(&raw, "--provider")
                    .map_err(|err| format!("{err}\n{}", usage(&program)))?;
            }
            "--sid" => {
                let raw = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --sid\n{}", usage(&program)))?;
                sid = parse_u16_arg(&raw, "--sid")
                    .map_err(|err| format!("{err}\n{}", usage(&program)))?;
            }
            "--user" => {
                username = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --user\n{}", usage(&program)))?;
            }
            "--pass" => {
                password = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --pass\n{}", usage(&program)))?;
            }
            "--des-key" => {
                des_key_hex = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --des-key\n{}", usage(&program)))?;
            }
            "--ecm" => {
                let raw = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --ecm\n{}", usage(&program)))?;
                ecm_section = Some(
                    parse_hex_bytes(&raw, "--ecm")
                        .map_err(|err| format!("{err}\n{}", usage(&program)))?,
                );
            }
            "--emm" => {
                let raw = rest
                    .next()
                    .ok_or_else(|| format!("missing value for --emm\n{}", usage(&program)))?;
                emm_section = Some(
                    parse_hex_bytes(&raw, "--emm")
                        .map_err(|err| format!("{err}\n{}", usage(&program)))?,
                );
            }
            "-h" | "--help" => {
                return Err(usage(&program));
            }
            other => {
                return Err(format!("unknown argument '{other}'\n{}", usage(&program)));
            }
        }
    }

    if username.is_empty() || password.is_empty() || des_key_hex.is_empty() {
        return Err(format!("required arguments are missing\n{}", usage(&program)));
    }

    let des_key_14 = cli_helpers::parse_des_key_14(&des_key_hex)?;

    Ok(CliArgs {
        config: NewcamdConfig {
            host,
            port,
            username,
            password,
            des_key_14,
            caid,
            provider,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        },
        sid,
        ecm_section,
        emm_section,
    })
}

mod cli_helpers {
    pub fn parse_des_key_14(hex: &str) -> Result<[u8; 14], String> {
    if hex.len() != 28 {
        return Err("NEWCAMD_DES_KEY_HEX must be exactly 28 hex chars (14 bytes)".to_string());
    }

    let mut out = [0_u8; 14];
    for (i, slot) in out.iter_mut().enumerate() {
        let from = i * 2;
        let to = from + 2;
        let chunk = &hex[from..to];
        *slot = u8::from_str_radix(chunk, 16)
            .map_err(|_| format!("invalid hex byte '{}' at positions {}..{}", chunk, from, to))?;
    }

    Ok(out)
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = match parse_cli_args() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            return;
        }
    };

    match NewcamdClient::connect(args.config).await {
        Ok(mut client) => {
            println!("Connected");
            println!("Card CAID: 0x{:04X}", client.card_data.caid);
            println!("Providers: {}", client.card_data.provider_count);

            let mut ran_test = false;

            if let Some(section) = args.ecm_section {
                ran_test = true;
                println!("Sending ECM test packet ({} bytes)...", section.len());
                let request = EcmRequest {
                    sid: args.sid,
                    caid: 0,
                    provider: 0,
                    section,
                };

                match client.send_ecm(&request).await {
                    Ok(response) if response.found => {
                        println!("ECM test OK, CW: {:02X?}", response.cw);
                    }
                    Ok(_) => {
                        println!("ECM test completed, CW not found");
                    }
                    Err(err) => {
                        eprintln!("ECM test failed: {err}");
                    }
                }
            }

            if let Some(section) = args.emm_section {
                ran_test = true;
                println!("Sending EMM test packet ({} bytes)...", section.len());
                match client.send_emm(&section, args.sid, 0, 0).await {
                    Ok(Some(packet)) => {
                        println!(
                            "EMM test acknowledged with command 0x{:02X} ({} bytes)",
                            packet.command,
                            packet.data.len()
                        );
                    }
                    Ok(None) => {
                        println!("EMM test sent, no explicit EMM ack packet received");
                    }
                    Err(err) => {
                        eprintln!("EMM test failed: {err}");
                    }
                }
            }

            if !ran_test {
                println!("No ECM/EMM test packet specified. Use --ecm <hex> and/or --emm <hex>.");
            }
        }
        Err(err) => {
            eprintln!("Connection failed: {err}");
        }
    }
}
