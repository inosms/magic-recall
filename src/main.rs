use clap::Parser;
use futures::executor::block_on;
use futures::prelude::*;
use futures::stream::StreamExt;
use libp2p::identity::Keypair;
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::Transport;
use libp2p::{identity, ping, Multiaddr, PeerId};
use rand::seq::SliceRandom;
use std::error::Error;

/// Store encrypted backups at remote nodes
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Mode of this node
    #[arg(value_enum, short, long)]
    mode: NodeMode,

    /// Peer ID of the remote peer to hole punch to.
    #[clap(short, long)]
    remote_peer_id: Option<PeerId>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum NodeMode {
    /// Use the default network bootstrap nodes.
    /// Use this for easy setup.
    UseDefaultNetwork,

    /// Create your own sub-network by creating a standalone bootstrap node.
    /// This will not connect to any default relays.
    NewBootstrapNode,
}

const DEFAULT_BOOTSTRAP_NODES: &[&str] =
    &["/ip4/13.231.196.201/tcp/8080/p2p/12D3KooWDJ66ykyQjUoaVvTQmwZFkPDKa4jPNZwiWQG6ACq3kAw9"];

fn _wait<T: libp2p::swarm::NetworkBehaviour>(swarm: &mut Swarm<T>, secs: u64)
where
    <T as NetworkBehaviour>::OutEvent: std::fmt::Debug,
{
    block_on(async {
        let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(secs)).fuse();
        loop {
            futures::select! {
                event = swarm.next() => {
                    dbg!(event);
                }
                _ = delay => {
                    // Likely listening on all interfaces now, thus continuing by breaking the loop.
                    break;
                }
            }
        }
    });
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    env_logger::init();

    // create a random new peer id
    let local_key: identity::Keypair = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {local_peer_id:?}");

    let mut swarm = block_on(build_swarm(local_key.clone()))?;

    match args.mode {
        NodeMode::UseDefaultNetwork => {
            // Listen on all interfaces
            swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
            _wait(&mut swarm, 2);

            DEFAULT_BOOTSTRAP_NODES
                .iter()
                .flat_map(|node| node.parse::<Multiaddr>())
                // TODO error handling
                .for_each(|node| {
                    dbg!(&node);
                    swarm.dial(node).ok();
                });
            _wait(&mut swarm, 2);
        }
        NodeMode::NewBootstrapNode => {
            // Listen on all interfaces
            swarm.listen_on("/ip4/0.0.0.0/tcp/8080".parse()?)?;
            _wait(&mut swarm, 2);
        }
    }

    if let Some(remote) = args.remote_peer_id {
        _wait(&mut swarm, 4);
        let relayed_remote_multiaddr = DEFAULT_BOOTSTRAP_NODES
            .choose(&mut rand::thread_rng())
            .expect("boostrap node exists")
            .parse::<Multiaddr>()
            .expect("valid multiaddress format")
            .with(libp2p::multiaddr::Protocol::P2pCircuit)
            .with(libp2p::multiaddr::Protocol::P2p(remote.into()));
        dbg!(&relayed_remote_multiaddr);
        dbg!(Into::<DialOpts>::into(relayed_remote_multiaddr.clone()));
        swarm.dial(relayed_remote_multiaddr);
    } else {
        _wait(&mut swarm, 4);
        let relayed_remote_multiaddr = DEFAULT_BOOTSTRAP_NODES
            .choose(&mut rand::thread_rng())
            .expect("boostrap node exists")
            .parse::<Multiaddr>()
            .expect("valid multiaddress format")
            .with(libp2p::multiaddr::Protocol::P2pCircuit);
        dbg!(&relayed_remote_multiaddr);
        dbg!(Into::<DialOpts>::into(relayed_remote_multiaddr.clone()));
        swarm.listen_on(relayed_remote_multiaddr);
    }

    block_on(async {
        loop {
            match swarm.next().await.expect("Infinite Stream.") {
                SwarmEvent::Behaviour(event) => {
                    println!("{event:?}")
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Listening on {address:?}");
                }
                evt => {
                    dbg!(evt);
                }
            }
        }
    })
}

async fn build_swarm(identity: Keypair) -> Result<Swarm<Behaviour2>, Box<dyn Error>> {
    let (transport, client) = build_transport(identity.clone()).await?;

    let behaviour = Behaviour2 {
        client: client,
        ping: libp2p::ping::Behaviour::new(ping::Config::new()),
        identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
            "/magicrecall/0.0.1".to_string(),
            identity.public(),
        )),
        dcutr: libp2p::dcutr::behaviour::Behaviour::new(),
        keep_alive: libp2p::swarm::keep_alive::Behaviour {},
        relay: libp2p::relay::v2::relay::Relay::new(
            PeerId::from(identity.public()),
            libp2p::relay::v2::relay::Config::default(),
        ),
    };

    Ok(Swarm::with_async_std_executor(
        transport,
        behaviour,
        PeerId::from(identity.public()),
    ))
}

/// copied from development_transport
/// TODO review this code
pub async fn build_transport(
    keypair: identity::Keypair,
) -> std::io::Result<(
    libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    libp2p::relay::v2::client::Client,
)> {
    let (relay_transport, client) = libp2p::relay::v2::client::Client::new_transport_and_behaviour(
        PeerId::from(keypair.public()),
    );

    // TODO add QUIC support
    let transport = {
        let dns_tcp = libp2p::dns::DnsConfig::system(libp2p::tcp::async_io::Transport::new(
            libp2p::tcp::Config::new().port_reuse(true),
        ))
        .await?;
        relay_transport.or_transport(dns_tcp)
    };

    Ok((
        transport
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(libp2p::noise::NoiseAuthenticated::xx(&keypair).unwrap())
            .multiplex(libp2p::core::upgrade::SelectUpgrade::new(
                libp2p::yamux::YamuxConfig::default(),
                libp2p::mplex::MplexConfig::default(),
            ))
            .timeout(std::time::Duration::from_secs(20))
            .boxed(),
        client,
    ))
}

#[derive(NetworkBehaviour)]
struct Behaviour2 {
    client: libp2p::relay::v2::client::Client,
    // TODO make not all nodes to relays maybe? Or if doing so limit the amount of data sent?
    relay: libp2p::relay::v2::relay::Relay,
    ping: ping::Behaviour,
    identify: libp2p::identify::Behaviour,
    dcutr: libp2p::dcutr::behaviour::Behaviour,
    keep_alive: libp2p::swarm::keep_alive::Behaviour,
    // TODO add mdns? or other peer discovery?
}
