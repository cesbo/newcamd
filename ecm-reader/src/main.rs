use anyhow::ensure;
use clap::Parser;
use libmpegts::{
    psi::Psi,
    slicer::TsSlicer,
};
use std::time::Duration;

use newcamd_lib::{EcmRequest, NewcamdClient, NewcamdConfig};

#[derive(Parser)]
#[command(about = "Read ECM sections from an MPEG-TS stream over HTTP")]
struct Args {
    /// HTTP MPEG-TS stream URL.
    url: String,

    /// ECM PID in decimal or hex form, for example 4660 or 0x1234.
    #[arg(value_parser = parse_pid)]
    ecm_pid: u16,
}

fn parse_pid(value: &str) -> Result<u16, String> {
    let pid = if let Some(hex) = value.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        value.parse()
    }
    .map_err(|_| format!("invalid PID: {value}"))?;

    if pid > 8191 {
        return Err("PID must be in range 0..=8191".into());
    }

    Ok(pid)
}

fn print_hex(data: &[u8]) {
    for (line, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}: ", line * 16);
        for byte in chunk {
            print!("{byte:02x} ");
        }
        println!();
    }
    println!();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    ensure!(
        args.url.starts_with("http://"),
        "only http:// URLs are supported"
    );

    let oscam_host = "bg.cesbo.com".to_string();
    let oscam_port: u16 = 9201;
    let caid: u16 = 0x09BD;
    let provider: u32 = 0;
    let sid: u16 = 1;
    let oscam_username = "test".to_string();
    let oscam_password = "test-123".to_string();
    let des_key_hex = "0102030405060708091011121314".to_string();
    //let mut ecm_section: Option<Vec<u8>> = None;
    //let mut emm_section: Option<Vec<u8>> = None;

    let des_key_14 = parse_des_key_14(&des_key_hex).map_err(|e| anyhow::anyhow!(e))?;

    let os_cam_config: NewcamdConfig = NewcamdConfig {
            host: oscam_host,
            port: oscam_port,
            username: oscam_username,
            password: oscam_password,
            des_key_14: des_key_14,
            caid,
            provider,
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
        };


    match NewcamdClient::connect(os_cam_config).await {
        Ok(mut client) => {
            println!("Connected");
            println!("Card CAID: 0x{:04X}", client.card_data.caid);
            println!("Providers: {}", client.card_data.provider_count);

            let mut response = reqwest::get(&args.url).await?.error_for_status()?;
            let mut slicer = TsSlicer::new();
            let mut psi = Psi::new(0);
            let mut current_table_id = None;

            while let Some(chunk) = response.chunk().await? {
                for packet in slicer.slice(&chunk).filter(|p| p.pid() == args.ecm_pid) {
                    let Some(section) = psi.assemble(&packet) else {
                        continue;
                    };

                    let Some(&table_id) = section.first() else {
                        continue;
                    };

                    if !matches!(table_id, 0x80 | 0x81) {
                        continue;
                    }

                    if current_table_id != Some(table_id) {
                        current_table_id = Some(table_id);
                        print_hex(section);
                        println!("Sending ECM test packet ({} bytes)...", section.len());
                        let request = EcmRequest {
                            sid: sid,
                            caid: caid,
                            provider: provider,
                            section: section.to_vec(),
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
                }
            }
        }
        Err(err) => {
            eprintln!("Connection failed: {err}");
        }
    }

    Ok(())
}

fn parse_des_key_14(hex: &str) -> Result<[u8; 14], String> {
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
