extern crate pretty_env_logger;
#[macro_use]
extern crate log;
use std::time::Duration;

use anyhow::{Error, Result};
use async_std::prelude::*;
use clap::Parser;
use futures::executor::block_on;
use futures::prelude::*;
use futures::stream::StreamExt;
use libp2p::identity::Keypair;
use libp2p::multiaddr::{ProtoStackIter, Protocol};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::Transport;
use libp2p::{identity, ping, Multiaddr, PeerId};
use rand::seq::SliceRandom;

mod magic_ether;
use magic_ether::magic_ether::*;

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

    /// Port on which the node should listen
    #[clap(short, long)]
    port: Option<u16>,

    /// List of additional bootstrap nodes
    #[clap(short, long)]
    bootstrap_nodes: Option<Vec<Multiaddr>>,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum NodeMode {
    /// Use the default network bootstrap nodes.
    /// Use this for easy setup.
    UseDefaultNetwork,

    /// Create your own sub-network by creating a standalone bootstrap node.
    /// This will not connect to any default relays.
    NewBootstrapNode,
}

#[async_std::main]
async fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();

    // create a random new peer id
    // TODO save and load from disk
    let local_key: identity::Keypair = identity::Keypair::generate_ed25519();
    let bootstrap_nodes = args
        .bootstrap_nodes
        .unwrap_or_default()
        .iter()
        .map(|addr| Ok((getPeerId(addr)?, addr.clone())))
        .collect::<Result<Vec<_>>>()?;

    let mut magic_ether = MagicEtherBuilder::new()
        .with_identity(local_key)
        .on_port(args.port.unwrap_or(0))
        .use_default_bootstrap_nodes(args.mode == NodeMode::UseDefaultNetwork)
        .add_bootstrap_nodes(bootstrap_nodes)
        .spawn_and_bootstrap()
        .await?;

    loop {
        magic_ether.find_relays().await;
        if let Some(remote_peer) = args.remote_peer_id {
            warn!("start finding {:?}", &remote_peer);
            let result = magic_ether.find_peer(remote_peer).await;
            warn!("found {:?}", result);
            std::thread::sleep(Duration::from_secs(60));
        }
        std::thread::sleep(Duration::from_secs(60));
    }

    std::thread::sleep(Duration::MAX);

    Ok(())

    // let local_peer_id = PeerId::from(local_key.public());

    // let mut swarm = block_on(build_swarm(local_key.clone()))?;

    // match args.mode {
    //     NodeMode::UseDefaultNetwork => {
    //         // Listen on all interfaces
    //         swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    //         _wait(&mut swarm, 2);

    //         DEFAULT_BOOTSTRAP_NODES
    //             .iter()
    //             .flat_map(|node| node.parse::<Multiaddr>())
    //             // TODO error handling
    //             .for_each(|node| {
    //                 dbg!(&node);
    //                 swarm.dial(node).ok();
    //             });
    //         _wait(&mut swarm, 2);
    //     }
    //     NodeMode::NewBootstrapNode => {
    //         // Listen on all interfaces
    //         swarm.listen_on("/ip4/0.0.0.0/tcp/8080".parse()?)?;
    //         _wait(&mut swarm, 2);
    //     }
    // }

    // if let Some(remote) = args.remote_peer_id {
    //     _wait(&mut swarm, 4);
    //     let relayed_remote_multiaddr = DEFAULT_BOOTSTRAP_NODES
    //         .choose(&mut rand::thread_rng())
    //         .expect("boostrap node exists")
    //         .parse::<Multiaddr>()
    //         .expect("valid multiaddress format")
    //         .with(libp2p::multiaddr::Protocol::P2pCircuit)
    //         .with(libp2p::multiaddr::Protocol::P2p(remote.into()));
    //     dbg!(&relayed_remote_multiaddr);
    //     dbg!(Into::<DialOpts>::into(relayed_remote_multiaddr.clone()));
    //     swarm.dial(relayed_remote_multiaddr);
    // } else {
    //     _wait(&mut swarm, 4);
    //     let relayed_remote_multiaddr = DEFAULT_BOOTSTRAP_NODES
    //         .choose(&mut rand::thread_rng())
    //         .expect("boostrap node exists")
    //         .parse::<Multiaddr>()
    //         .expect("valid multiaddress format")
    //         .with(libp2p::multiaddr::Protocol::P2pCircuit);
    //     dbg!(&relayed_remote_multiaddr);
    //     dbg!(Into::<DialOpts>::into(relayed_remote_multiaddr.clone()));
    //     swarm.listen_on(relayed_remote_multiaddr);
    // }

    // block_on(async {
    //     loop {
    //         match swarm.next().await.expect("Infinite Stream.") {
    //             SwarmEvent::Behaviour(event) => {
    //                 println!("{event:?}")
    //             }
    //             SwarmEvent::NewListenAddr { address, .. } => {
    //                 println!("Listening on {address:?}");
    //             }
    //             evt => {
    //                 dbg!(evt);
    //             }
    //         }
    //     }
    // })
}

fn getPeerId(addr: &Multiaddr) -> Result<PeerId> {
    addr.iter()
        .last()
        .and_then(|protocol| match protocol {
            Protocol::P2p(id) => Some(PeerId::from_multihash(id).ok()?),
            _ => None,
        })
        .ok_or(Error::msg("Expected PeerId at end of address"))
}
