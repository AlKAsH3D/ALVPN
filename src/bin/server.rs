use std::{
    error::Error,
    fs,
    net::SocketAddr,
    path::Path,
};

use ALVPN::protocol::{Packet, VERSION};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cert_path = Path::new("certs/server.der");
    let key_path = Path::new("certs/server.key.der");

    if !cert_path.exists() || !key_path.exists() {
        fs::create_dir_all("certs")?;

        let generated =
            rcgen::generate_simple_self_signed(
                vec!["alvpn.local".to_string()]
            )?;

        fs::write(
            cert_path,
            generated.cert.der().as_ref(),
        )?;

        fs::write(
            key_path,
            generated.key_pair.serialize_der(),
        )?;

        println!("TLS certificate generated.");
    }

    let cert = rustls::pki_types::CertificateDer::from(
        fs::read(cert_path)?
    );

    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        fs::read(key_path)?
    );

    let config = quinn::ServerConfig::with_single_cert(
        vec![cert],
        key.into(),
    )?;

    let addr: SocketAddr =
        "0.0.0.0:4433".parse()?;

    let endpoint =
        quinn::Endpoint::server(config, addr)?;

    println!("GujaVPN server listening on {addr}");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            let connection = match incoming.await {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("Connection failed: {error}");
                    return;
                }
            };

            println!(
                "Connected: {}",
                connection.remote_address()
            );

            while let Ok((mut send, mut recv)) =
                connection.accept_bi().await
            {
                tokio::spawn(async move {
                    let data = match recv.read_to_end(65_540).await {
                        Ok(data) => data,
                        Err(error) => {
                            eprintln!("Read failed: {error}");
                            return;
                        }
                    };

                    let request = match Packet::decode(&data) {
                        Ok(packet) => packet,
                        Err(error) => {
                            eprintln!("Invalid packet: {error}");
                            return;
                        }
                    };

                    let response = match request {
                        Packet::Hello(version)
                        if version == VERSION =>
                            {
                                Packet::Hello(VERSION)
                            }
                        Packet::Data(data) => Packet::Data(data),
                        Packet::KeepAlive => Packet::KeepAlive,
                        Packet::Disconnect => Packet::Disconnect,
                        _ => Packet::Disconnect,
                    };

                    if let Ok(encoded) = response.encode() {
                        let _ = send.write_all(&encoded).await;
                        let _ = send.finish();
                    }
                });
            }
        });
    }

    Ok(())
}