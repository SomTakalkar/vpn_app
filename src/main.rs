use std::net::Ipv4Addr;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "vpn")]
#[command(author = "Som Takalkar")]
#[command(version = "0.1.0")]
#[command(about = "Custom Layer 3/4 Encrypted VPN Daemon in Rust", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Phase 1: Interactive TUN device playground for intercepting and parsing raw IP packets
    TunPlayground {
        #[arg(short, long, default_value = "tun0")]
        name: String,

        #[arg(short, long, default_value = "10.8.0.2")]
        ip: Ipv4Addr,

        #[arg(short, long, default_value = "255.255.255.0")]
        netmask: Ipv4Addr,

        #[arg(short, long, default_value_t = 1400)]
        mtu: i32,
    },

    /// Run as VPN Client
    Client {
        #[arg(short, long)]
        server: String,

        #[arg(short, long, default_value = "10.8.0.2")]
        tun_ip: Ipv4Addr,
    },

    /// Run as VPN Server
    Server {
        #[arg(short, long, default_value = "0.0.0.0:51820")]
        bind: String,

        #[arg(short, long, default_value = "10.8.0.1")]
        tun_ip: Ipv4Addr,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::TunPlayground { name, ip, netmask, mtu } => {
            run_tun_playground(name, ip, netmask, mtu).await?;
        }
        Commands::Client { server, tun_ip } => {
            info!("Starting VPN Client connecting to {} with TUN IP {}...", server, tun_ip);
            // Hooked into Phase 2 / 3
        }
        Commands::Server { bind, tun_ip } => {
            info!("Starting VPN Server listening on {} with TUN IP {}...", bind, tun_ip);
            // Hooked into Phase 2 / 3
        }
    }

    Ok(())
}

/// Phase 1: TUN Playground runner
async fn run_tun_playground(name: String, ip: Ipv4Addr, netmask: Ipv4Addr, mtu: i32) -> Result<()> {
    info!("==========================================================");
    info!("Starting TUN Playground (Phase 1)");
    info!("Interface: {}, IP: {}, Netmask: {}, MTU: {}", name, ip, netmask, mtu);
    info!("==========================================================");

    let mut config = tun::Configuration::default();
    config
        .name(&name)
        .address(ip)
        .netmask(netmask)
        .mtu(mtu)
        .up();

    #[cfg(target_os = "linux")]
    config.platform(|p| {
        p.packet_information(false);
    });

    let dev = tun::create_as_async(&config)
        .context("Failed to create TUN device. Ensure you have root/CAP_NET_ADMIN privileges")?;

    info!("TUN device '{}' is UP! Listening for incoming packets...", name);
    info!("Try opening another terminal and running: ping -c 3 {}", ip);

    use tokio::io::AsyncReadExt;
    let mut dev = dev;
    let mut buf = [0u8; 2048];

    let mut packet_count: u64 = 0;

    loop {
        let n = dev.read(&mut buf).await.context("Failed reading from TUN device")?;
        packet_count += 1;

        if let Some(header) = vpn::packet::Ipv4PacketHeader::parse(&buf[..n]) {
            info!(
                "[#{} | {} bytes] {} -> {} | Proto: {} | TTL: {}",
                packet_count,
                n,
                header.src_ip,
                header.dst_ip,
                header.protocol,
                header.ttl
            );
        } else {
            warn!("[#{} | {} bytes] Non-IPv4 or truncated packet received", packet_count, n);
        }
    }
}
