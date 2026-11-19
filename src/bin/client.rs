use std::{
    env,
    error::Error,
    fs,
    net::SocketAddr,
    sync::Arc,
};

use ALVPN::protocol::{Packet, VERSION};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server = env::args()
        .nth(1)
        .ok_or("Usage: client IP:4433")?;

    let address: SocketAddr = server.parse()?;

    let certificate =
        rustls::pki_types::CertificateDer::from(
            fs::read("certs/server.der")?
        );

    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;

    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let quic_config = quinn::ClientConfig::new(
        Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?
        )
    );

    let bind_address: SocketAddr = if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
        .parse()?;

    let mut endpoint =
        quinn::Endpoint::client(bind_address)?;

    endpoint.set_default_client_config(quic_config);

    println!("Connecting to {address}...");

    let connection = endpoint
        .connect(address, "gujavpn.local")?
        .await?;

    println!("TLS connection established.");

    let (mut send, mut recv) =
        connection.open_bi().await?;

    let hello = Packet::Hello(VERSION).encode()?;

    send.write_all(&hello).await?;
    send.finish()?;

    let reply = recv.read_to_end(65_540).await?;
    let packet = Packet::decode(&reply)?;

    match packet {
        Packet::Hello(version) if version == VERSION => {
            println!("GujaVPN protocol v{version} ready.");
        }
        other => {
            return Err(format!(
                "Unexpected server response: {other:?}"
            ).into());
        }
    }

    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;

    Ok(())
}