/*******************

Team members and IDs:
Yasiel  Barroso    6051279 
Dairon  Rodriguez  6177575 
Michael Biichle    3331049

Github link:
https://github.com/ybarr042/MyRouting.git

*******************/

package net.floodlightcontroller.myrouting;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.ImmutablePort;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;

import java.util.*;

import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryListener;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.myrouting.MyRouting.Node;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.Link;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.staticflowentry.IStaticFlowEntryPusherService;
import net.floodlightcontroller.topology.NodePortTuple;

import org.openflow.util.HexString;
import org.slf4j.Logger;

public class MyRouting implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	protected IDeviceService deviceProvider;
	protected ILinkDiscoveryService linkProvider;
	Collection<? extends IDevice> devices;

	protected Map<Long, IOFSwitch> switches = null;
	protected Map<Link, LinkInfo> links;

	protected static int uniqueFlow;
	protected ILinkDiscoveryService lds;
	protected IStaticFlowEntryPusherService flowPusher;
	protected boolean executeOnce = false;
	Map<String, ArrayList<Node>> graph = new HashMap<String, ArrayList<Node>>();
	Map<Long, ArrayList<Node>> mapHost = new HashMap<Long, ArrayList<Node>>();

	@Override
	public String getName() {
		return MyRouting.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return (type.equals(OFType.PACKET_IN) && (name.equals("devicemanager") || name.equals("topology"))
				|| name.equals("forwarding"));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(ILinkDiscoveryService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		linkProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		flowPusher = context.getServiceImpl(IStaticFlowEntryPusherService.class);
		lds = context.getServiceImpl(ILinkDiscoveryService.class);

	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		// Initialize providers
		if (this.switches == null) {
			this.switches = floodlightProvider.getAllSwitchMap();
		}
		devices = deviceProvider.getAllDevices();

		// Build graph data structure
		configureSwitchMap(graph);
		if (!executeOnce) {
			// Build the switch map
			printSwitches(graph);
			executeOnce = true;
		}

		// eth is the packet sent by a switch and received by floodlight.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		// We process only IP packets of type 0x0800.
		if (eth.getEtherType() != 0x0800) {
			return Command.CONTINUE;
		} else {
			System.out.println("*** New flow packet");

			// Parse the incoming packet.
			OFPacketIn pi = (OFPacketIn) msg;
			OFMatch match = new OFMatch();
			match.loadFromPacket(pi.getPacketData(), pi.getInPort());

			// Obtain source and destination IPs.
			// ...
			System.out.println("srcIP: " + match.getNetworkSourceCIDR().toString().split("/")[0]);
			System.out.println("dstIP: " + match.getNetworkDestinationCIDR().toString().split("/")[0]);

			/*
			 * Get source and destination device from list of devices
			 */
			Long srcDevice = (long) 0;
			Long dstIPDevice = (long) 0;

			try {
				for (IDevice device : devices) {
					// System.out.println("match IP:"+ match.getNetworkDestination());
					// System.out.println("match IP CIDR:"+ match.getNetworkDestinationCIDR());
					// System.out.println("device IP:"+ device.getIPv4Addresses()[0]);
					// System.out.println("device MAC:"+ device.getMACAddressString());

					if (device.getIPv4Addresses()[0] == match.getNetworkSource()) {

						srcDevice = device.getDeviceKey();
						// srcDevice = device.getAttachmentPoints()[0].getSwitchDPID();
						// System.out.println("Src foud: "+srcDevice.toString() );
					}
					if (device.getIPv4Addresses()[0] == match.getNetworkDestination()) {

						dstIPDevice = device.getDeviceKey();
						// dstIPDevice = device.getAttachmentPoints()[0].getSwitchDPID();
						// System.out.println("Dst foud:" + dstIPDevice.toString());
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}

			// Calculate the path using Dijkstra's algorithm.
			try {
				configureHostMap(mapHost, graph);
				ShortesPath sp = new ShortesPath(graph.size());

				sp.dijkstra(graph, "H"+srcDevice);
				Integer cost = sp.dist.get("H"+dstIPDevice);
				System.out.println("The cost from "+ srcDevice+" to "+dstIPDevice+" is: "+cost);
			} catch (Exception e) {
				e.printStackTrace();
			}

			Route route = null;

			System.out.println("route: " + "1 2 3");

			// Write the path into the flow tables of the switches on the path.
			if (route != null) {
				installRoute(route.getPath(), match);
			}

			return Command.STOP;
		}
	}

	private void configureHostMap(Map<Long, ArrayList<Node>> mapHost, Map<String, ArrayList<Node>> graph) {
		try {
			/**
			 * Add all the list of all host in the network to the HashMap
			 */
			for (IDevice device : devices) {
				// System.out.println("host : " + device.getDeviceKey());
				// System.out.println("host atta: " +
				// device.getAttachmentPoints()[0].getSwitchDPID());
				if (!mapHost.containsKey(device.getDeviceKey())) {
					mapHost.put(device.getDeviceKey(), new ArrayList<Node>());
					String switchId = "S"+device.getAttachmentPoints()[0].getSwitchDPID();
					mapHost.get(device.getDeviceKey()).add(new Node(switchId, calculateWeight()));
				}
				
			}

			for (Long hostIdLong : mapHost.keySet()) {
				String hostId = "H"+hostIdLong;
				graph.put(hostId, mapHost.get(hostIdLong));
			}

		} catch (Exception e) {
			e.printStackTrace();

		}
	}

	private int calculateWeight() {
		return 1;
	}

	private void configureSwitchMap(Map<String, ArrayList<Node>> graph) {
		/**
		 * Add all the list of all switches in the network to the HashMap
		 */
		for (IOFSwitch iofsw : switches.values()) {
			String switchId = "S"+iofsw.getId();
			ArrayList<Node> items = new ArrayList<Node>();
			graph.put(switchId, items);
		}

		/**
		 * Add neighbors to the list
		 */

		Map<Link, LinkInfo> links = linkProvider.getLinks();
		for (Link link : links.keySet()) {
			String switchIdSrc = "S"+link.getSrc();
			String switchIdDst = "S"+link.getDst();
			if (graph.containsKey(switchIdSrc)) {
				graph.get(switchIdSrc).add(new Node(switchIdDst, calculateWeight()));
			}
		}
	}

	private void printSwitches(Map<String, ArrayList<Node>> graph) {
		System.out.println("*** Print topology");
		Map<Long, ArrayList<String>> tmp = new HashMap<>();
		for (String element1 : graph.keySet()) {
			ArrayList<String> neighbors = new ArrayList<String>();
			for (int i = 0; i < graph.get(element1).size(); i++) {
				neighbors.add(graph.get(element1).get(i).node.toString().substring(1));
				Collections.sort(neighbors);

			}
			tmp.put(Long.decode(element1.substring(1)), neighbors);
		}
		for(Long switchId: tmp.keySet()) {
			ArrayList<String> neighbors = tmp.get(switchId);
			System.out.println(
					"switch " + switchId + " neighbors: " + neighbors.toString().replace("[", "").replace("]", ""));
		}
	}

	// Install routing rules on switches.
	private void installRoute(List<NodePortTuple> path, OFMatch match) {

		OFMatch m = new OFMatch();

		m.setDataLayerType(Ethernet.TYPE_IPv4).setNetworkSource(match.getNetworkSource())
				.setNetworkDestination(match.getNetworkDestination());

		for (int i = 0; i <= path.size() - 1; i += 2) {
			short inport = path.get(i).getPortId();
			m.setInputPort(inport);
			List<OFAction> actions = new ArrayList<OFAction>();
			OFActionOutput outport = new OFActionOutput(path.get(i + 1).getPortId());
			actions.add(outport);

			OFFlowMod mod = (OFFlowMod) floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
			mod.setCommand(OFFlowMod.OFPFC_ADD).setIdleTimeout((short) 0).setHardTimeout((short) 0).setMatch(m)
					.setPriority((short) 105).setActions(actions)
					.setLength((short) (OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
			flowPusher.addFlow("routeFlow" + uniqueFlow, mod, HexString.toHexString(path.get(i).getNodeId()));
			uniqueFlow++;
		}
	}

	// Class to represent a node in the graph
	class Node implements Comparator<Node> {
		public String node;
		public int cost;

		public Node() {
		}

		public Node(String node, int cost) {
			this.node = node;
			this.cost = cost;
		}

		@Override
		public int compare(Node node1, Node node2) {
			if (node1.cost < node2.cost)
				return -1;
			if (node1.cost > node2.cost)
				return 1;
			return 0;
		}
	}

	public class ShortesPath {
		// private Long dist[];
		private Set<String> settled;
		private PriorityQueue<Node> pq;
		private int V; // Number of vertices
		// List<List<Node>> adj;
		Map<String, ArrayList<Node>> adj;
		Map<String, Integer> dist;

		public ShortesPath(int V) {
			this.V = V;
			dist = new HashMap<String, Integer>();
			settled = new HashSet<String>();
			pq = new PriorityQueue<Node>(V, new Node());
		}

		// Function for Dijkstra's Algorithm
		public void dijkstra(Map<String, ArrayList<Node>> adj, String src) {
			this.adj = adj;

			 for (String id : this.adj.keySet()) {
				 this.dist.put(id, Integer.MAX_VALUE);
			 }

			// Add source node to the priority queue
			pq.add(new Node(src, 0));

			// Distance to the source is 0
			dist.put(src, 0);

			while (settled.size() != V && !pq.isEmpty()) {
				// remove the minimum distance node
				// from the priority queue
				String u = pq.remove().node;
				System.out.print("Distance array: ");
				for(String a : dist.keySet()) {
					System.out.print(a+":"+dist.get(a)+", ");
				}

				// adding the node whose distance is
				// finalized
				settled.add(u);

				e_Neighbours(u);
			}
		}

		// Function to process all the neighbours
		// of the passed node
		private void e_Neighbours(String u) {
			int edgeDistance = -1;
			int newDistance = -1;

			// All the neighbors of v
			for (int i = 0; i < adj.get(u).size(); i++) {
				Node v = adj.get(u).get(i);

				// If current node hasn't already been processed
				if (!settled.contains(v.node)) {
					edgeDistance = v.cost;
					newDistance = dist.get(u) + edgeDistance;

					// If new distance is cheaper in cost
					if (newDistance < dist.get(v.node))
						dist.put(v.node, newDistance);

					// Add the current node to the queue
					pq.add(new Node(v.node, dist.get(v.node)));
				}
			}

		}

	}

}
