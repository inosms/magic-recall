use std::{
    collections::{hash_map, HashMap},
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use anyhow::Result;

use async_std::task::{block_on, spawn};
use futures_timer::Delay;
use libp2p::{
    autonat::{Event, NatStatus},
    identity::{self, Keypair},
    kad::{store::MemoryStore, Kademlia},
    multiaddr::Protocol,
    swarm::{IntoConnectionHandler, SwarmEvent},
    Multiaddr, PeerId,
};

use futures::{channel::mpsc, prelude::*};
use libp2p::ping;
use libp2p::swarm::{NetworkBehaviour, Swarm};
use libp2p::Transport;

pub struct MagicEtherBuilder {
    identity: Option<Keypair>,
    port: Option<u16>,
    use_ipv6: bool,
    bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    use_default_bootstrap_nodes: bool,
}

const DEFAULT_BOOTSTRAP_NODES: &[(&str, &str)] = &[(
    "12D3KooWDJ66ykyQjUoaVvTQmwZFkPDKa4jPNZwiWQG6ACq3kAw9",
    "/ip4/13.231.196.201/tcp/8080",
)];

impl MagicEtherBuilder {
    pub fn new() -> Self {
        Self {
            identity: None,
            port: None,
            use_ipv6: false,
            bootstrap_nodes: vec![],
            use_default_bootstrap_nodes: true,
        }
    }

    pub fn with_identity(mut self, identity: Keypair) -> Self {
        self.identity = Some(identity);
        self
    }

    pub fn on_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    pub fn use_default_bootstrap_nodes(mut self, use_default_bootstrap_nodes: bool) -> Self {
        self.use_default_bootstrap_nodes = use_default_bootstrap_nodes;
        self
    }

    pub fn use_ipv6(mut self, use_ipv6: bool) -> Self {
        self.use_ipv6 = use_ipv6;
        self
    }

    pub fn add_bootstrap_node(mut self, peerId: PeerId, addr: Multiaddr) -> Self {
        self.bootstrap_nodes.push((peerId, addr));
        self
    }

    pub fn add_bootstrap_nodes(mut self, nodes: Vec<(PeerId, Multiaddr)>) -> Self {
        self.bootstrap_nodes.extend(nodes.into_iter());
        self
    }

    pub async fn spawn_and_bootstrap(self) -> Result<MagicEther> {
        let identity = self
            .identity
            .unwrap_or_else(|| identity::Keypair::generate_ed25519());

        let mut bootstrap_nodes = self.bootstrap_nodes;
        if self.use_default_bootstrap_nodes {
            bootstrap_nodes.extend(
                DEFAULT_BOOTSTRAP_NODES
                    .iter()
                    .filter_map(|(peerId, addr)| Some((peerId.parse().ok()?, addr.parse().ok()?))),
            )
        }

        MagicEther::spawn_and_bootstrap(
            identity,
            self.port.unwrap_or(0),
            self.use_ipv6,
            bootstrap_nodes,
        )
        .await
    }
}

pub struct MagicEther {
    identity: Keypair,
    local_peer_id: PeerId,
    bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    command_sender: mpsc::UnboundedSender<Command>,
}

impl MagicEther {
    async fn spawn_and_bootstrap(
        identity: Keypair,
        port: u16,
        use_ipv6: bool,
        bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    ) -> Result<Self> {
        let local_peer_id = PeerId::from(identity.public());
        info!("local peer id is {:?}", local_peer_id);

        let (relay_transport, client) =
            libp2p::relay::v2::client::Client::new_transport_and_behaviour(local_peer_id);

        // TODO add QUIC support
        let transport = {
            let dns_tcp = block_on(libp2p::dns::DnsConfig::system(
                libp2p::tcp::async_io::Transport::new(libp2p::tcp::Config::new().port_reuse(true)),
            ))?;
            relay_transport.or_transport(dns_tcp)
        };

        let transport = transport
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(libp2p::noise::NoiseAuthenticated::xx(&identity).unwrap())
            .multiplex(libp2p::core::upgrade::SelectUpgrade::new(
                libp2p::yamux::YamuxConfig::default(),
                libp2p::mplex::MplexConfig::default(),
            ))
            .timeout(std::time::Duration::from_secs(20))
            .boxed();

        let behaviour = Behaviour {
            client: client,
            ping: libp2p::ping::Behaviour::new(ping::Config::new()),
            identify: libp2p::identify::Behaviour::new(libp2p::identify::Config::new(
                "/magic-ether/1".to_string(),
                identity.public(),
            )),
            dcutr: libp2p::dcutr::behaviour::Behaviour::new(),
            keep_alive: libp2p::swarm::keep_alive::Behaviour {},
            relay: libp2p::relay::v2::relay::Relay::new(
                local_peer_id,
                libp2p::relay::v2::relay::Config::default(),
            ),
            mdns: libp2p::mdns::async_io::Behaviour::new(Default::default())?,
            kad: Kademlia::new(local_peer_id, MemoryStore::new(local_peer_id)),
            autonat: libp2p::autonat::Behaviour::new(local_peer_id, Default::default()),
        };

        let mut swarm = Swarm::with_async_std_executor(transport, behaviour, local_peer_id);

        let listen_addr = Multiaddr::empty()
            .with(if use_ipv6 {
                Protocol::from(Ipv6Addr::UNSPECIFIED)
            } else {
                Protocol::from(Ipv4Addr::UNSPECIFIED)
            })
            .with(Protocol::Tcp(port));

        // TODO make async
        swarm.listen_on(listen_addr)?;
        let (command_sender, command_receiver) = mpsc::unbounded();

        let eventProcessor = MagicEtherEventProcessor::new(command_receiver, swarm);
        spawn(eventProcessor.run());

        let mut magic_ether = Self {
            identity: identity,
            local_peer_id: local_peer_id,
            bootstrap_nodes: bootstrap_nodes,
            command_sender: command_sender,
        };

        magic_ether.bootstrap().await?;
        Ok(magic_ether)
    }

    async fn bootstrap(&mut self) -> Result<()> {
        let mut bootstrapping_successful = false;
        let mut lastError = Ok(());
        // TODO retry bootstrapping on failure?
        // TODO async bootstrapping?
        for (peerId, addr) in std::mem::take(&mut self.bootstrap_nodes).iter() {
            match self.add_ether_node(peerId.clone(), addr.clone()).await {
                Ok(_) => bootstrapping_successful = true,
                Err(e) => {
                    error!(
                        "error bootstrapping peerId={:?} addr={:?} error={:?}",
                        peerId, addr, e
                    );
                    lastError = Err(e);
                }
            }
        }

        if (bootstrapping_successful) {
            Ok(())
        } else {
            lastError
        }
    }

    // add bootstrap node?
    // load bootstrap nodes from file?
    // discover non-friend node?
    // discover relays

    /// Add a node (not necessarily friend node) which is on the same Kademlia DHT.
    /// This can be a bootstrap node or any other node.
    pub async fn add_ether_node(&mut self, peerId: PeerId, multiAddr: Multiaddr) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::Dial {
                peer_id: peerId,
                peer_addr: multiAddr,
                sender: sender,
            })
            .await
            .expect("command channel to not be dropped");
        receiver.await?
    }

    /// Use the DHT to query the address of the given peer and connect to the node if possible
    /// TODO get channel
    pub fn connect_to(&mut self, peerId: PeerId) {
        unimplemented!()
    }

    /// Send a friend request to the given PeerId.
    /// Also send some request details for the other party to accept.
    /// TODO specify T
    pub fn friend_request<T>(&mut self, peerId: PeerId, requestDetails: T) {
        unimplemented!()
    }

    // save known connected peers to file and load on build?
}

struct MagicEtherEventProcessor {
    command_receiver: mpsc::UnboundedReceiver<Command>,
    swarm: Swarm<Behaviour>,
    pending_dial: HashMap<PeerId, oneshot::Sender<Result<()>>>,
}

impl MagicEtherEventProcessor {
    fn new(command_receiver: mpsc::UnboundedReceiver<Command>, swarm: Swarm<Behaviour>) -> Self {
        Self {
            command_receiver,
            swarm,
            pending_dial: Default::default(),
        }
    }

    pub async fn run(mut self) {
        loop {
            futures::select! {
                event = self.swarm.next() => self.handle_event(event.expect("Swarm stream to be infinite.")).await,
                command = self.command_receiver.next() => match command {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down the network event loop.
                    None=>  return,
                },
            }
        }
    }

    async fn handle_event<THandlerError: std::fmt::Debug>(
        &mut self,
        event: SwarmEvent<BehaviourEvent, THandlerError>,
    ) {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(Event::StatusChanged { old, new })) => {
                match (old.clone(), new.clone()) {
                    (NatStatus::Private, NatStatus::Public(_))
                    | (NatStatus::Unknown, NatStatus::Public(_)) => {
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .start_providing(String::from("RELAY").into_bytes().into())
                            .map_err(|e| error!("was unable to promote relay status: {:?}", e))
                            .ok();
                        info!("announcing this as public relay node");
                        // TODO remove relayed external address
                    }
                    (NatStatus::Public(_), NatStatus::Private)
                    | (NatStatus::Public(_), NatStatus::Unknown) => {
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .stop_providing(&String::from("RELAY").into_bytes().into());
                        info!("stop announcing this as public relay node");
                    }
                    _ => { /* do nothing */ }
                }
                info!("old state {:?} new state {:?}", old, new);

                // When we have gone private try to find a public relay
                if new == NatStatus::Private {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .get_providers(String::from("RELAY").into_bytes().into());
                }
            }
            // SwarmEvent::Behaviour(ComposedEvent::Kademlia(
            //     KademliaEvent::OutboundQueryProgressed {
            //         id,
            //         result: QueryResult::StartProviding(_),
            //         ..
            //     },
            // )) => {
            //     let sender: oneshot::Sender<()> = self
            //         .pending_start_providing
            //         .remove(&id)
            //         .expect("Completed query to be previously pending.");
            //     let _ = sender.send(());
            // }
            // SwarmEvent::Behaviour(ComposedEvent::Kademlia(
            //     KademliaEvent::OutboundQueryProgressed {
            //         id,
            //         result:
            //             QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders {
            //                 providers, ..
            //             })),
            //         ..
            //     },
            // )) => {
            //     if let Some(sender) = self.pending_get_providers.remove(&id) {
            //         sender.send(providers).expect("Receiver not to be dropped");

            //         // Finish the query. We are only interested in the first result.
            //         self.swarm
            //             .behaviour_mut()
            //             .kademlia
            //             .query_mut(&id)
            //             .unwrap()
            //             .finish();
            //     }
            // }
            // SwarmEvent::Behaviour(ComposedEvent::Kademlia(
            //     KademliaEvent::OutboundQueryProgressed {
            //         result:
            //             QueryResult::GetProviders(Ok(GetProvidersOk::FinishedWithNoAdditionalRecord {
            //                 ..
            //             })),
            //         ..
            //     },
            // )) => {}
            // SwarmEvent::Behaviour(ComposedEvent::Kademlia(_)) => {}
            // SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
            //     request_response::Event::Message { message, .. },
            // )) => match message {
            //     request_response::Message::Request {
            //         request, channel, ..
            //     } => {
            //         self.event_sender
            //             .send(Event::InboundRequest {
            //                 request: request.0,
            //                 channel,
            //             })
            //             .await
            //             .expect("Event receiver not to be dropped.");
            //     }
            //     request_response::Message::Response {
            //         request_id,
            //         response,
            //     } => {
            //         let _ = self
            //             .pending_request_file
            //             .remove(&request_id)
            //             .expect("Request to still be pending.")
            //             .send(Ok(response.0));
            //     }
            // },
            // SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
            //     request_response::Event::OutboundFailure {
            //         request_id, error, ..
            //     },
            // )) => {
            //     let _ = self
            //         .pending_request_file
            //         .remove(&request_id)
            //         .expect("Request to still be pending.")
            //         .send(Err(Box::new(error)));
            // }
            // SwarmEvent::Behaviour(ComposedEvent::RequestResponse(
            //     request_response::Event::ResponseSent { .. },
            // )) => {}
            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer_id = *self.swarm.local_peer_id();
                info!(
                    "Local node is listening on {:?}",
                    address.with(Protocol::P2p(local_peer_id.into()))
                );
            }
            // SwarmEvent::IncomingConnection { .. } => {}
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                if endpoint.is_dialer() {
                    if let Some(sender) = self.pending_dial.remove(&peer_id) {
                        let _ = sender.send(Ok(()));
                    }
                }
                info!("Connected to {:?} via endpoint {:?}", peer_id, endpoint);
            }
            // SwarmEvent::ConnectionClosed { .. } => {}
            // SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            //     if let Some(peer_id) = peer_id {
            //         if let Some(sender) = self.pending_dial.remove(&peer_id) {
            //             let _ = sender.send(Err(Box::new(error)));
            //         }
            //     }
            // }
            // SwarmEvent::IncomingConnectionError { .. } => {}
            // SwarmEvent::Dialing(peer_id) => eprintln!("Dialing {peer_id}"),
            e => debug!("unhandled event {e:?}"),
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                if let hash_map::Entry::Vacant(e) = self.pending_dial.entry(peer_id) {
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, peer_addr.clone());
                    match self
                        .swarm
                        .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                    {
                        Ok(()) => {
                            e.insert(sender);
                        }
                        Err(e) => {
                            let _ = sender.send(Err(e.into()));
                        }
                    }
                } else {
                    todo!("Already dialing peer.");
                }
            }
        }
    }
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    // We need to be able to punch holes through NATs in order to access
    // non-public nodes. For this a Relay Client & Relay (Server) is needed.
    // In practice all nodes behind a NAT need to be only Client and public nodes
    // need to be relay.
    //
    // With only Client & Relay communication is relayed over the public node, but we
    // want to be able to punch holes, which is why DCUtR is also added.
    //
    // TODO: make only public nodes Relays? Or is it OK to have all nodes behave as Relays?
    client: libp2p::relay::v2::client::Client,
    relay: libp2p::relay::v2::relay::Relay,
    dcutr: libp2p::dcutr::behaviour::Behaviour,

    // In order to automatically find public Relays we also need autonat & autorelay
    autonat: libp2p::autonat::Behaviour,
    // TODO autorelay

    // For local peer discovery we rely on mDNS
    mdns: libp2p::mdns::async_io::Behaviour,

    // In order to find the physical addresses of our peers we use Kademlia
    kad: libp2p::kad::Kademlia<MemoryStore>,

    // TODO is this needed?
    identify: libp2p::identify::Behaviour,
    keep_alive: libp2p::swarm::keep_alive::Behaviour,
    ping: ping::Behaviour,
}

#[derive(Debug)]
enum Command {
    Dial {
        peer_id: PeerId,
        peer_addr: Multiaddr,
        sender: oneshot::Sender<Result<()>>,
    },
}
