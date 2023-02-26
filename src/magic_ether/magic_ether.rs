use async_trait::async_trait;
use std::{
    collections::{hash_map, HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use serde::{Deserialize, Serialize};

use anyhow::{anyhow, Result};

use async_std::{
    stream::IntoStream,
    task::{block_on, spawn},
};
use futures_timer::Delay;
use libp2p::{
    autonat::{Event, NatStatus},
    core::upgrade::{read_length_prefixed, write_length_prefixed},
    identity::{self, Keypair},
    kad::{
        store::{MemoryStore, RecordStore},
        GetClosestPeersOk, GetProvidersOk, GetProvidersResult, Kademlia, KademliaEvent,
        ProgressStep, QueryId, QueryResult,
    },
    multiaddr::Protocol,
    request_response::{
        ProtocolName, ProtocolSupport, RequestId, RequestResponseEvent, ResponseChannel,
    },
    swarm::{derive_prelude::ListenerId, AddressScore, IntoConnectionHandler, SwarmEvent},
    Multiaddr, PeerId,
};

use futures::{
    channel::mpsc::{self, UnboundedSender},
    prelude::*,
};
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

const DEFAULT_BOOTSTRAP_NODES: &[(&str, &str)] = &[
    (
        "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "/dnsaddr/bootstrap.libp2p.io",
    ),
    (
        "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
        "/dnsaddr/bootstrap.libp2p.io",
    ),
    (
        "QmZa1sAxajnQjVM8WjWXoMbmPd7NsWhfKsPkErzpm9wGkp",
        "/dnsaddr/bootstrap.libp2p.io",
    ),
    (
        "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
        "/dnsaddr/bootstrap.libp2p.io",
    ),
    (
        "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dw",
        "/dnsaddr/bootstrap.libp2p.io",
    ),
];

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

#[derive(Clone)]
pub struct MagicEther {
    identity: Keypair,
    local_peer_id: PeerId,
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
                libp2p::tcp::async_io::Transport::new(
                    libp2p::tcp::Config::new(), //    TODO .port_reuse(true)
                ),
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
                "/inosms/magic-ether/0.1.0".to_string(),
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
            request_response: libp2p::request_response::RequestResponse::new(
                EtherExchangeCodec(),
                std::iter::once((EtherExchangeProtocol(), ProtocolSupport::Full)),
                Default::default(),
            ),
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
            command_sender: command_sender,
        };

        magic_ether.bootstrap(bootstrap_nodes).await?;

        Ok(magic_ether)
    }

    async fn bootstrap(&mut self, bootstrap_nodes: Vec<(PeerId, Multiaddr)>) -> Result<()> {
        let mut bootstrapping_successful = false;
        let mut lastError = Ok(());
        // TODO retry bootstrapping on failure?
        // TODO async bootstrapping?
        for (peerId, addr) in bootstrap_nodes.into_iter() {
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

        if bootstrapping_successful {
            self.bootstrap_kad().await;
            Ok(())
        } else {
            lastError
        }
    }

    /// Add a node (not necessarily friend node) which is on the same Kademlia DHT.
    /// This can be a bootstrap node or any other node.
    async fn add_ether_node(&mut self, peerId: PeerId, multiAddr: Multiaddr) -> Result<()> {
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

    /// Make this local node known to the other nodes on the Kademlia DHT.
    /// !!! Note that this must be called after at least one node has been successfully dialed. !!!
    async fn bootstrap_kad(&mut self) {
        self.command_sender
            .send(Command::BootstrapKad)
            .await
            .expect("command channel to not be dropped");
    }

    async fn find_peer(&mut self, peer_id: PeerId) -> Result<Vec<Multiaddr>> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .send(Command::FindPeer { peer_id, sender })
            .await
            .expect("command channel to not be dropped");
        receiver.await?
    }

    /// Poll all peers that try to open a remote channel with this given peer
    pub async fn poll_connection_requests(&self) -> Result<impl Stream<Item = ConnectionRequest>> {
        let (channel_sender, channel_receiver) = oneshot::channel();
        self.command_sender
            .clone()
            .send(Command::RegisterIncomingConnectionRequestListener {
                sender: channel_sender,
            })
            .await?;
        let mut connection_request_receiver = channel_receiver.await?.ok_or(anyhow!(
            "connection requests are already being polled somewhere else!"
        ))?;
        Ok(async_stream::stream! {
            while let Some(connection_request) = connection_request_receiver.next().await {
                yield connection_request;
            }
        })
    }

    /// Accept a remote channel request from the given peer id.
    /// If the given peer id is not currently pending or not connected return an error.
    pub async fn accept_connection_request(&self, peer_id: PeerId) -> Result<RemoteConnection> {
        unimplemented!()
    }

    /// Reject an incoming request and block the peer. This disconnects the peer and also
    /// blocks the peer from further connecting.
    /// TODO implement blocking and saving to disk.
    pub async fn reject_connection_request(&self, peer_id: PeerId) {
        unimplemented!()
    }

    /// Request connection a remote channel to the given peer id.
    pub async fn request_connection_to(&self, peer_id: PeerId) -> Result<RemoteConnection> {
        // TODO: oh god rewrite this
        let mut client = self.clone();

        // first find the peer and its multi addresses for connecting
        let addresses = client.find_peer(peer_id).await?;

        // for every address try to connect to the peer
        for addr in addresses {
            if client.add_ether_node(peer_id, addr).await.is_ok() {
                match client.send_connection_request_to(peer_id).await {
                    Ok(_) => return Ok(RemoteConnection {}),
                    // if we were able to connect to the client but then cot rejected for our connection
                    // we do not need to try other addresses as we got rejected.
                    Err(e) => return Err(e),
                }
                // TODO: if the answer is OK also list the peer as one to be reconnected automatically on connection loss
                //         (maybe do this with a channel to the RemoteConnection?
                //         If the channel gets closed = RemoteConnection got dropped -> stop?)
            }
            // else do nothing and try another address
        }

        anyhow::bail!("unable to get connection to {}", peer_id);
    }

    async fn send_connection_request_to(&mut self, peer_id: PeerId) -> Result<()> {
        let (sender, receiver) = oneshot::channel();
        self.command_sender
            .clone()
            .send(Command::RequestConnection {
                peer_id: peer_id,
                sender: sender,
            })
            .await
            .expect("command channel to not be dropped");
        receiver.await?
    }

    // save known connected peers to file and load on build?
}

struct MagicEtherEventProcessor {
    command_receiver: mpsc::UnboundedReceiver<Command>,
    swarm: Swarm<Behaviour>,
    pending_dial: HashMap<PeerId, oneshot::Sender<Result<()>>>,
    pending_search: HashMap<PeerId, Vec<oneshot::Sender<Result<Vec<Multiaddr>>>>>,
    pending_search_ids: HashMap<QueryId, PeerId>,
    auto_relay: AutoRelay,

    /// for every incoming connection request the client needs to decide
    /// whether to accept or reject the request.
    /// For this a channel supplying an object containing the PeerIds is created.
    /// The receiver end can only ever exist once hence the Option<> type.
    /// If obtained once it can not be obtained another time.
    incoming_connection_request_sender: mpsc::UnboundedSender<ConnectionRequest>,
    incoming_connection_request_receiver: Option<mpsc::UnboundedReceiver<ConnectionRequest>>,

    /// Whenever a remote peer initiates a connection request the requests needs to be answered or rejected.
    /// As this handling is done asynchronously a sender (held by the clients deciding whether to accept or reject)
    /// and a receiver held by the event loop is needed.
    /// The sender is cloned every time a new incoming connection request is received.
    connection_request_answer_command_sender:
        mpsc::UnboundedSender<(ResponseChannel<EtherResponse>, EtherResponse)>,
    connection_request_answer_command_receiver:
        mpsc::UnboundedReceiver<(ResponseChannel<EtherResponse>, EtherResponse)>,

    /// Stores all pending outgoing connection requests done by this node
    pending_connection_requests:
        HashMap<libp2p::request_response::RequestId, oneshot::Sender<Result<()>>>,
}

impl MagicEtherEventProcessor {
    fn new(command_receiver: mpsc::UnboundedReceiver<Command>, swarm: Swarm<Behaviour>) -> Self {
        let (sender, receiver) = mpsc::unbounded();
        let (answer_sender, answer_receiver) = mpsc::unbounded();
        Self {
            command_receiver,
            swarm,
            pending_dial: Default::default(),
            pending_search: Default::default(),
            pending_search_ids: Default::default(),
            auto_relay: Default::default(),
            incoming_connection_request_sender: sender,
            incoming_connection_request_receiver: Some(receiver),
            connection_request_answer_command_sender: answer_sender,
            connection_request_answer_command_receiver: answer_receiver,
            pending_connection_requests: Default::default(),
        }
    }

    pub async fn run(mut self) {
        let mut relay_search_trigger_emitter =
            async_std::stream::interval(Duration::from_secs(60)).fuse();

        loop {
            futures::select! {
                event = self.swarm.next() => self.handle_event(event.expect("Swarm stream to be infinite.")).await,
                command = self.command_receiver.next() => match command {
                    Some(c) => self.handle_command(c).await,
                    // Command channel closed, thus shutting down the network event loop.
                    None =>  return,
                },
                connection_request_answer = self.connection_request_answer_command_receiver.next() => match connection_request_answer {
                    Some(answer) => self.handle_connection_request_answer(answer).await,
                    None => {},
                },
                _ = relay_search_trigger_emitter.next() => self.initiate_relay_search(),
            }
        }
    }

    /// Query the DHT for all public relays.
    ///
    /// This should probably be done periodically. However if this overloads the network
    /// maybe have a better strategy?
    fn initiate_relay_search(&mut self) {
        info!("[autorelay/search] initiate relay search");
        self.swarm
            .behaviour_mut()
            .kad
            // TODO: Maybe use something better than just "RELAY"? CID?
            .get_providers(String::from("RELAY").into_bytes().into());
    }

    /// Announce this node as a "relay provider".
    /// This makes the address of this peer available for lookup via the "find provider"
    /// query of the DHT.
    ///
    /// This method should only be called when this node is reachable from the outside
    /// in order to not pollute the relay query space.
    fn announce_this_node_as_relay(&mut self) {
        self.swarm
            .behaviour_mut()
            .kad
            // TODO: Maybe use something better than just "RELAY"? CID?
            .start_providing(String::from("RELAY").into_bytes().into())
            // TODO: proper error handling
            .map_err(|e| error!("was unable to promote relay status: {:?}", e))
            .ok();
        warn!("announcing this as public relay node");
    }

    /// Stop announcing this node as a "relay provider".
    /// This should be called whenever this node has gone private as judged by e.g. AutoNat.
    fn stop_announcing_this_node_as_relay(&mut self) {
        self.swarm
            .behaviour_mut()
            .kad
            // TODO: Maybe use something better than just "RELAY"? CID?
            .stop_providing(&String::from("RELAY").into_bytes().into());
        warn!("stop announcing this as public relay node");
    }

    async fn handle_connection_request_answer(
        &mut self,
        connection_request_answer: (ResponseChannel<EtherResponse>, EtherResponse),
    ) {
        self.swarm
            .behaviour_mut()
            .request_response
            .send_response(connection_request_answer.0, connection_request_answer.1)
            .ok();
        // TODO: error handling! --> return an error to the caller
    }

    /// Handle an incoming AutoNat event.
    /// This is used for determining whether to announce this node as a relay or not.
    ///
    /// Every node in magic-ether can function as a relay node if it is public to provide
    /// distributed hole punching functionality to the network.
    ///
    /// Also if the current node has gone private make sure that this node tries to automatically
    /// connect to relays via AutoRelay.
    fn handle_autonat_event(&mut self, event: &libp2p::autonat::Event) {
        if let Event::StatusChanged { old, new } = event {
            warn!(
                "[autonat/Event::StatusChanged] old state {:?} new state {:?}",
                &old, &new
            );

            match (old, new) {
                // if has gone public announce
                (_, &NatStatus::Public(_)) => {
                    self.announce_this_node_as_relay();
                    self.auto_relay
                        .set_mode(AutoRelayMode::SEARCH_RELAYS_WITHOUT_CONNECTING);
                }
                // if has gone private or unknown stop announcing
                (_, &NatStatus::Private | &NatStatus::Unknown) => {
                    self.stop_announcing_this_node_as_relay();
                    self.auto_relay
                        .set_mode(AutoRelayMode::SEARCH_RELAYS_AND_CONNECT);
                }
                _ => { /* do nothing */ }
            }
        }
        // Ignore other Events such as Inbound / Outbound probes
    }

    /// Handle a request_response event which handles all communication with connected nodes used for
    /// package transfer.
    async fn handle_request_response_event(
        &mut self,
        event: RequestResponseEvent<EtherRequest, EtherResponse>,
    ) {
        match event {
            RequestResponseEvent::Message { peer, message } => match message {
                libp2p::request_response::RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    match request {
                        EtherRequest::ConnectionRequest => {
                            self.incoming_connection_request_sender
                                .send(ConnectionRequest {
                                    ether_response_channel: channel,
                                    command_response_channel: self
                                        .connection_request_answer_command_sender
                                        .clone(),
                                    peer_id: peer,
                                })
                                .await
                                .ok(); // TODO handle error
                        }
                    }
                }
                libp2p::request_response::RequestResponseMessage::Response {
                    request_id,
                    response,
                } => match response {
                    EtherResponse::ConnectionRequestAccepted => {
                        if let Some(channel) = self.pending_connection_requests.remove(&request_id) {
                            channel.send(Ok(())).ok(); // TODO: error handling
                        }
                    }
                    EtherResponse::ConnectionRequestRejected => {
                        if let Some(channel) = self.pending_connection_requests.remove(&request_id) {
                            channel
                                .send(Err(anyhow!(
                                    "The other peer rejected the connection request"
                                )))
                                .ok(); // TODO: error handling
                        }
                    }
                },
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
            } => {
                if let Some(channel) = self.pending_connection_requests.remove(&request_id) {
                    channel.send(Err(anyhow!("{:?}", error))).ok(); // TODO: error handling
                }
            }
            RequestResponseEvent::InboundFailure {
                peer,
                request_id,
                error,
            } => {
                if let Some(channel) = self.pending_connection_requests.remove(&request_id) {
                    channel.send(Err(anyhow!("{:?}", error))).ok(); // TODO: error handling
                }
            }
            RequestResponseEvent::ResponseSent { peer, request_id } => todo!(),
        }
    }

    async fn handle_event<THandlerError: std::fmt::Debug>(
        &mut self,
        event: SwarmEvent<BehaviourEvent, THandlerError>,
    ) {
        info!("[magic-ether/Event]: {:?}", event);
        error!(
            "[magic-ether/Status]: {:?}",
            self.swarm.connected_peers().collect::<Vec<_>>()
        );
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Autonat(e)) => {
                self.handle_autonat_event(&e);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Mdns(libp2p::mdns::Event::Discovered(
                addresses,
            ))) => {
                for (peer_id, peer_addr) in addresses {
                    warn!(
                        "connecting to local peer {:?} at {:?}",
                        &peer_id, &peer_addr
                    );
                    self.swarm
                        .behaviour_mut()
                        .kad
                        .add_address(&peer_id, peer_addr.clone());
                    self.swarm
                        .dial(peer_addr.with(Protocol::P2p(peer_id.into())))
                        .map_err(|e| error!("was unable to connect to local peer: {:?}", e))
                        .ok();
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(
                KademliaEvent::OutboundQueryProgressed {
                    result:
                        QueryResult::GetProviders(Ok(GetProvidersOk::FoundProviders { key, providers })),
                    ..
                },
            )) => {
                error!(
                    "[KAD/Query] found providers for {:?}: {:?}",
                    &key, &providers
                );
                if key == String::from("RELAY").into_bytes().into() {
                    providers.iter().for_each(|provider| {
                        let (peerId, addrs) = (
                            provider.clone(),
                            self.swarm.behaviour_mut().addresses_of_peer(provider),
                        );
                        self.auto_relay.add_relay_candidate_address(peerId, addrs);
                    });
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Kad(
                KademliaEvent::OutboundQueryProgressed {
                    result: QueryResult::GetClosestPeers(Ok(GetClosestPeersOk { peers, .. })),
                    step: ProgressStep { count: _, last },
                    id,
                    ..
                },
            )) => {
                warn!("Got query progress");
                for (peer, _) in &self.pending_search {
                    if peers.contains(&peer) {
                        if !Swarm::is_connected(&self.swarm, &peer) {
                            // TODO: Kademlia might not be caching the address of the peer.
                            // TODO get only external addresses here before dialing?
                            Swarm::dial(&mut self.swarm, *peer).unwrap();
                            warn!("dial peer {:?}", &peer);
                            self.pending_search_ids.remove(&id);
                        }
                    }
                    warn!(
                        "{:?} has addresses {:?}",
                        &peer,
                        self.swarm.behaviour_mut().addresses_of_peer(&peer)
                    );
                }
                if last {
                    if let Some(pid) = self.pending_search_ids.remove(&id) {
                        if let Some(senders) = self.pending_search.remove(&pid) {
                            for sender in senders {
                                sender
                                    .send(Err(anyhow::Error::msg("no address found")))
                                    .expect("channel not to be dropped");
                            }
                        }
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(
                libp2p::identify::Event::Received {
                    peer_id,
                    info:
                        libp2p::identify::Info {
                            protocol_version,
                            agent_version,
                            listen_addrs,
                            protocols,
                            observed_addr,
                            ..
                        },
                },
            )) => {
                warn!("identified {:?}", &peer_id);
                if let Some(senders) = self.pending_search.remove(&peer_id) {
                    for sender in senders {
                        sender
                            .send(Ok(listen_addrs.clone()))
                            .expect("channel to not be closed");
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::RequestResponse(e)) => {
                self.handle_request_response_event(e);
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                let local_peer_id = *self.swarm.local_peer_id();
                warn!(
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
                error!("Connected to {:?} via endpoint {:?}", peer_id, endpoint);
            }
            SwarmEvent::ListenerClosed {
                listener_id,
                addresses,
                reason,
            } => {
                self.auto_relay.listener_closed(listener_id);
            }
            SwarmEvent::ListenerError { listener_id, error } => {
                self.auto_relay.listener_closed(listener_id);
            }
            _ => debug!("no handler"),
        }
    }

    async fn find_peer(
        &mut self,
        peer_id: PeerId,
        sender: oneshot::Sender<Result<Vec<Multiaddr>>>,
    ) {
        // if we are already aware of addresses of the peer do not query
        let peer_addresses = self.swarm.behaviour_mut().kad.addresses_of_peer(&peer_id);
        if !peer_addresses.is_empty() {
            sender
                .send(Ok(peer_addresses))
                .expect("receiver not to be dropped");
            warn!("found peer address already");
        } else {
            // if there is no current query running start one
            if let hash_map::Entry::Vacant(e) = self.pending_search.entry(peer_id) {
                let query_id = self.swarm.behaviour_mut().kad.get_closest_peers(peer_id);
                warn!("start query");
                e.insert(vec![sender]);
                self.pending_search_ids.insert(query_id, peer_id.clone());
            }
            // else if there is a query currently running just append the channel for getting the results
            else {
                warn!("already started query");
                self.pending_search
                    .get_mut(&peer_id)
                    .map(|v| v.push(sender));
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::FindPeer { peer_id, sender } => {
                warn!("handle find peer");
                self.find_peer(peer_id, sender).await;
            }
            Command::Dial {
                peer_id,
                peer_addr,
                sender,
            } => {
                // no need to dial a connected peer
                if self.swarm.is_connected(&peer_id) {
                    let _ = sender.send(Ok(()));
                }
                // if not connected start dialing process
                else {
                    if let hash_map::Entry::Vacant(e) = self.pending_dial.entry(peer_id) {
                        self.swarm
                            .behaviour_mut()
                            .kad
                            .add_address(&peer_id, peer_addr.clone());
                        let addr = if peer_addr.ends_with(
                            &Multiaddr::empty().with(Protocol::P2p(peer_id.clone().into())),
                        ) {
                            peer_addr
                        } else {
                            peer_addr.with(Protocol::P2p(peer_id.into()))
                        };
                        match self.swarm.dial(addr) {
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
            Command::BootstrapKad => {
                self.swarm.behaviour_mut().kad.bootstrap().ok();
            }
            Command::RegisterIncomingConnectionRequestListener { sender } => {
                sender.send(self.incoming_connection_request_receiver.take());
            }
            Command::RequestConnection { peer_id, sender } => {
                let request_id = self
                    .swarm
                    .behaviour_mut()
                    .request_response
                    .send_request(&peer_id, EtherRequest::ConnectionRequest);
                self.pending_connection_requests.insert(request_id, sender);
            }
        }

        self.auto_relay.poll(&mut self.swarm);
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

    // For actually sending packages across the wire
    request_response: libp2p::request_response::RequestResponse<EtherExchangeCodec>,

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
    FindPeer {
        peer_id: PeerId,
        sender: oneshot::Sender<Result<Vec<Multiaddr>>>,
    },
    RegisterIncomingConnectionRequestListener {
        sender: oneshot::Sender<Option<mpsc::UnboundedReceiver<ConnectionRequest>>>,
    },
    RequestConnection {
        peer_id: PeerId,
        sender: oneshot::Sender<Result<()>>,
    },
    BootstrapKad,
}

const MAX_RELAY_CONNECTIONS: usize = 3;

struct AutoRelay {
    mode: AutoRelayMode,

    candidates: HashMap<PeerId, HashSet<Multiaddr>>,

    pending_relay_connections: HashMap<ListenerId, PeerId>,
    established_relay_connections: HashSet<PeerId>,
}

impl Default for AutoRelay {
    fn default() -> Self {
        Self {
            mode: AutoRelayMode::SEARCH_RELAYS_WITHOUT_CONNECTING,
            candidates: Default::default(),
            pending_relay_connections: Default::default(),
            established_relay_connections: Default::default(),
        }
    }
}

impl AutoRelay {
    /// Add a relay candidate with the given addresses.
    /// If already present extends the set if not inserts the set.
    pub fn add_relay_candidate_address(&mut self, peerId: PeerId, addrs: Vec<Multiaddr>) {
        self.candidates
            .entry(peerId)
            .or_default()
            .extend(addrs.into_iter());
    }

    /// From the currently known relay candidates get a new one.
    /// Do not return one that is currently used or one that has a pending reservation.
    fn get_relay_candidate(&self) -> Option<(PeerId, HashSet<Multiaddr>)> {
        let currently_used_relays = self
            .pending_relay_connections
            .values()
            .chain(self.established_relay_connections.iter())
            .collect::<HashSet<_>>();
        // TODO: get a really random one
        self.candidates
            .keys()
            .collect::<HashSet<_>>()
            .difference(&currently_used_relays)
            .next()
            .and_then(|&peerId| Some((peerId.clone(), self.candidates.get(peerId)?.clone())))
    }

    // TODO
    fn on_swarm_event() {
        // on connection -> ???
        // define this as a protocol??
        unimplemented!()
    }

    fn on_relay_client_event() {
        // when reservation gets accepted or failed
        unimplemented!()
    }

    // TODO
    fn poll(&mut self, swarm: &mut Swarm<Behaviour>) {
        // periodically search for new candidates (maybe stop if you already have some good ones?)
        // if in connection mode (SEARCH_RELAYS_AND_CONNECT) && currently not connected to N relays:
        //   get good/random relay
        //   start reservation
        //
        // check all relays: is still connected?
        //   if no: delete from list

        // TODO interval
        if self.mode == AutoRelayMode::SEARCH_RELAYS_AND_CONNECT
            && self.established_relay_connections.len() < MAX_RELAY_CONNECTIONS
        {
            let (candidate_peer_id, candidate_addr) = if let Some(r) = self.get_relay_candidate() {
                r
            } else {
                return; // TODO
            };
            for addr in candidate_addr {
                if let Ok(listener_id) =
                    swarm.listen_on(Self::build_listen_addr(candidate_peer_id, addr))
                {
                    self.pending_relay_connections
                        .insert(listener_id, candidate_peer_id);
                }
            }
        }
    }

    pub fn set_mode(&mut self, mode: AutoRelayMode) {
        self.mode = mode;
    }

    pub fn listener_closed(&mut self, listener_id: ListenerId) {
        self.pending_relay_connections
            .retain(|&k, _| k != listener_id);
        // self.established_relay_connections.retain(|&k| k != listener_id);
        // TODO
    }

    fn build_listen_addr(peerId: PeerId, addr: Multiaddr) -> Multiaddr {
        // already contains peerId?
        let has_p2p_protocol = addr
            .iter()
            .last()
            .map(|prot| matches!(prot, Protocol::P2p(_)))
            .unwrap_or_default();
        // if already contains just put circuit:
        if has_p2p_protocol {
            addr.with(Protocol::P2pCircuit)
        }
        // otherwise also add the peer id
        else {
            addr.with(Protocol::P2p(peerId.into()))
                .with(Protocol::P2pCircuit)
        }
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
enum AutoRelayMode {
    SEARCH_RELAYS_WITHOUT_CONNECTING,
    SEARCH_RELAYS_AND_CONNECT,
}

// TODO: Relay rating

enum RelayState {
    ADDRESS_KNOWN,

    /// Started connection and waiting for approval, start time is stored in Instant
    /// If longer than a given time has elapsed the attempt is seen as failure
    RESERVATION_PENDING(std::time::Instant),
    RESERVED,
}

#[derive(Debug)]
pub struct RemoteConnection {}
impl RemoteConnection {
    pub async fn send_request() -> Result<()> {
        unimplemented!()
    }

    pub async fn poll_incoming_events() -> Result<()> {
        // TODO: poll connection event: Disconnect / Ban / etc. / Request(TRequest)
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
struct EtherExchangeProtocol();
#[derive(Clone)]
struct EtherExchangeCodec();

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
enum EtherRequest {
    ConnectionRequest,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
enum EtherResponse {
    ConnectionRequestAccepted,
    ConnectionRequestRejected,
}

impl ProtocolName for EtherExchangeProtocol {
    fn protocol_name(&self) -> &[u8] {
        "/ether-exchange/1".as_bytes()
    }
}

#[async_trait]
impl libp2p::request_response::RequestResponseCodec for EtherExchangeCodec {
    type Protocol = EtherExchangeProtocol;
    type Request = EtherRequest;
    type Response = EtherResponse;

    async fn read_request<T>(
        &mut self,
        _: &EtherExchangeProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 1_000_000).await?;

        if vec.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }

        Ok(rmp_serde::from_slice(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?)
    }

    async fn read_response<T>(
        &mut self,
        _: &EtherExchangeProtocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let vec = read_length_prefixed(io, 500_000_000).await?; // update transfer maximum

        if vec.is_empty() {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }

        Ok(rmp_serde::from_slice(&vec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?)
    }

    async fn write_request<T>(
        &mut self,
        _: &EtherExchangeProtocol,
        io: &mut T,
        request: EtherRequest,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(
            io,
            rmp_serde::to_vec(&request)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        )
        .await?;
        io.close().await?;

        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _: &EtherExchangeProtocol,
        io: &mut T,
        response: EtherResponse,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(
            io,
            rmp_serde::to_vec(&response)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
        )
        .await?;
        io.close().await?;

        Ok(())
    }
}

/// Whenever a remote peer tries to connect to us for exchanging data
/// they need to send a connection request.
/// This connection request can then be accepted or rejected (or ignored)
/// by the other side.
///
/// In case the ConnectionRequests gets accepted a bidirectional tunnel is set up
/// which enables the two nodes to communicate over the network.
///
/// In case the ConnectionRequests gets rejected the requesting peer gets banned
/// (TODO: maybe don't ban?)
#[derive(Debug)]
pub struct ConnectionRequest {
    ether_response_channel: ResponseChannel<EtherResponse>,
    command_response_channel:
        mpsc::UnboundedSender<(ResponseChannel<EtherResponse>, EtherResponse)>,
    peer_id: PeerId,
}

impl ConnectionRequest {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub async fn accept(mut self) -> RemoteConnection {
        self.command_response_channel
            .send((
                self.ether_response_channel,
                EtherResponse::ConnectionRequestAccepted,
            ))
            .await
            .expect("command channel not to be closed");
        RemoteConnection {}
    }

    pub async fn reject(mut self) {
        self.command_response_channel
            .send((
                self.ether_response_channel,
                EtherResponse::ConnectionRequestRejected,
            ))
            .await
            .expect("command channel not to be closed");
    }
}

// TODO: reject on drop?
