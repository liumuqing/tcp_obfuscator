#![feature(ip_bits)]

use tokio;
use tokio::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio_tun::Tun;
use std::net::Ipv4Addr;

use pnet::packet::{Packet, MutablePacket, PacketSize};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, Ipv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket, TcpFlags};
use pnet::packet::tcp;
use pnet::packet::ipv4;

use ipnet::Ipv4Net;

use std::sync::Arc;
use std::process::exit;
use tokio::sync::Mutex;

use tracing::{info, error};

#[derive(Clone)]
struct NetMapping {
    local: Ipv4Net,
    remote: Ipv4Net,
}

async fn nat_packet(network_mapping: NetMapping, writer: Arc<Mutex<WriteHalf<Tun>>>, buf: Vec<u8>) {

    let ipv4 = Ipv4Packet::new(&buf).unwrap();
    let tcp = TcpPacket::new(ipv4.payload()).unwrap();

    let mut new_ipv4_buf = vec![0 as u8; buf.len()];
    let mut new_ipv4 = MutableIpv4Packet::new(&mut new_ipv4_buf).unwrap();
    new_ipv4.clone_from(&ipv4);

    let mut direction_forward = false;
    if network_mapping.local.contains(&ipv4.get_destination()) && ipv4.get_source() == network_mapping.local.addr() {
        let new_dest = Ipv4Addr::from_bits((ipv4.get_destination().to_bits() & network_mapping.local.hostmask().to_bits()) | network_mapping.remote.network().to_bits());
        new_ipv4.set_destination(new_dest);
        new_ipv4.set_source(ipv4.get_destination());
        direction_forward = true;
    }

    if network_mapping.remote.contains(&ipv4.get_source()) && network_mapping.local.contains(&ipv4.get_destination()) {
        let new_source= Ipv4Addr::from_bits((ipv4.get_source().to_bits() & network_mapping.remote.hostmask().to_bits()) | network_mapping.local.network().to_bits());
        new_ipv4.set_source(new_source);
        new_ipv4.set_destination(network_mapping.local.addr());
    }
    if (!direction_forward) || 
        (tcp.get_flags() & (TcpFlags::SYN | TcpFlags::FIN | TcpFlags::RST | TcpFlags::URG | TcpFlags::CWR | TcpFlags::ECE)) != 0 || 
        tcp.payload().len() <= 2 {

        let mut tcp_buf = vec![0 as u8; tcp.packet_size() + tcp.payload().len()];
        let mut new_tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();

        new_tcp.clone_from(&tcp);
        new_tcp.set_checksum(
            tcp::ipv4_checksum(&new_tcp.to_immutable(), &new_ipv4.get_source(), &new_ipv4.get_destination()));

        new_ipv4.set_payload(&new_tcp.packet()[..new_tcp.packet_size() + tcp.payload().len()]);
        new_ipv4.set_total_length(new_ipv4.get_header_length() as u16 * 4 + new_tcp.packet_size() as u16 + tcp.payload().len() as u16);
        new_ipv4.set_checksum(ipv4::checksum(&new_ipv4.to_immutable()));

        writer.lock().await.write(&new_ipv4.packet()[..new_ipv4.packet_size()]).await.unwrap();

    } else {

        let payload_length = tcp.payload().len();

        let segments = [
            (2, payload_length, false),
            (1, payload_length, true),
            (0, 2, true),
        ];

        for (start, end, good) in segments {
            let mut new_payload = Vec::from(&tcp.payload()[start..end]);
            if !good {
                new_payload.copy_from_slice(&vec![0x41; end-start]);
            }

            let mut tcp_buf = vec![0 as u8; tcp.packet_size() + new_payload.len()];
            tcp_buf[..tcp.packet_size()].copy_from_slice(&tcp.packet()[..tcp.packet_size()]);
            let mut new_tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
            new_tcp.set_payload(&new_payload);

            new_ipv4.set_total_length(new_ipv4.get_header_length() as u16 * 4 + new_tcp.packet_size() as u16 + new_tcp.payload().len() as u16);

            new_tcp.set_sequence(tcp.get_sequence().wrapping_add(start as u32));
            new_tcp.set_checksum(
                tcp::ipv4_checksum(&new_tcp.to_immutable(), &new_ipv4.get_source(), &new_ipv4.get_destination()));
            new_ipv4.set_payload(&new_tcp.packet()[..new_tcp.packet_size() + new_tcp.payload().len()]);
            new_ipv4.set_checksum(ipv4::checksum(&new_ipv4.to_immutable()));
            writer.lock().await.write(&new_ipv4.packet()[..new_ipv4.packet_size()]).await.unwrap();

            tokio::time::sleep(Duration::from_millis(1)).await;

        }
    }
}

/// just a system
fn system(cmdline: &str, allow_fail: bool) {
    use std::process::Command;
    info!("executing `{}`", cmdline);
    let args: Vec<&str> = cmdline.split(" ").collect();
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]);
    let status = cmd.status();

    let Ok(status) = status else { error!("cannot execute `{}`", cmdline); exit(1)};

    if !status.success()  && !allow_fail{
        error!("`{}` returns non-zero", cmdline);
        exit(1);
    }
}

fn init_tun(network_mapping: &NetMapping, tun_name: &str, interface: &str, public_ip: &str) {

    system(&format!("sysctl -w net.ipv4.ip_forward=1"), false);

    system(&format!("ip addr add {} dev {}", network_mapping.local.to_string(), tun_name), false);
    system(&format!("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", tun_name), true);
    system(&format!("iptables -t nat -A POSTROUTING -o {} -j MASQUERADE", tun_name), false);

    system(&format!("sudo iptables -t nat -D POSTROUTING -s {} -o {} -j SNAT --to {}", network_mapping.local.trunc().to_string(), interface, public_ip), true);
    system(&format!("sudo iptables -t nat -A POSTROUTING -s {} -o {} -j SNAT --to {}", network_mapping.local.trunc().to_string(), interface, public_ip), false);

    info!("setup tun and iptables done.");
}

fn uninit_tun(network_mapping: &NetMapping, tun_name: &str, interface: &str, public_ip: &str) {
    system(&format!("ip addr del {} dev {}", network_mapping.local.to_string(), tun_name), true);
    system(&format!("iptables -t nat -D POSTROUTING -o {} -j MASQUERADE", tun_name), true);
    system(&format!("sudo iptables -t nat -D POSTROUTING -s {} -o {} -j SNAT --to {}", network_mapping.local.trunc().to_string(), interface, public_ip), true);
}

use clap::Parser;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// the remote network, e.g 192.168.0.0/16
    #[arg(short, long)]
    remote: String,

    /// the local network, with a local address. e.g 127.168.0.0/16
    #[arg(short, long)]
    local: String,


    /// the public interface, e.g eth1, ens160, etc.
    #[arg(short, long)]
    interface: String,

    /// the public ip address, e.g 172.16.90.128, etc.
    #[arg(short, long)]
    public_ip: String,
}


#[tokio::main]
async fn main() {
    use tracing_subscriber;
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let net_mapping = NetMapping {
        local: args.local.parse().unwrap_or_else(|_|{error!("cannot parse local network `{}`", args.local); exit(1);}),
        remote: args.remote.parse().unwrap_or_else(|_|{error!("cannot parse remote network `{}`", args.remote); exit(1);}),
    };
    if net_mapping.remote.trunc() != net_mapping.remote {
        error!("remote network should be a pure network (e.g {})", net_mapping.remote.trunc());
        exit(1);
    }



    info!("creating tun...");
    let tun = Tun::builder()
        .name("obfuscator_tun")            // if name is empty, then it is set by kernel.
        .tap(false)          // false (default): TUN, true: TAP.
        .packet_info(false)  // false: IFF_NO_PI, default is true.
        .up()                // or set it up manually using `sudo ip link set <tun-name> up`.
        .try_build()         // or `.try_build_mq(queues)` for multi-queue support.
        .unwrap_or_else(|_| {
            error!("cannot create tun, run with root?");
            exit(1);
        });
    info!("tun created, name: {}", tun.name());

    init_tun(&net_mapping, tun.name(), &args.interface, &args.public_ip);
    
    let net_mapping_to_move = net_mapping.clone();
    let tun_name = tun.name().to_owned();


    let (mut reader, writer) = tokio::io::split(tun);
    let writer = Arc::new(Mutex::new(writer));
    let net_mapping = net_mapping.clone();
    info!("running..");
    tokio::task::spawn( async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            let mut buf = Vec::from(&buf[..n]);

            let Some(ipv4) = Ipv4Packet::new(&mut buf) else { continue } ;
            if ipv4.get_version() != 4 { continue }
            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { continue }

            let Some(_tcp) = TcpPacket::new(ipv4.payload()) else {continue};

            // forward this packet
            let writer = writer.clone();
            tokio::task::spawn(
                nat_packet(net_mapping.clone(), writer, buf)
                );
        }
    } );

    tokio::signal::ctrl_c().await.expect("failed to listen for event");
    uninit_tun(&net_mapping_to_move, &tun_name, &args.interface, &args.public_ip);
    info!("bye!");
}
