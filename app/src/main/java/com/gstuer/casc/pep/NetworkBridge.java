package com.gstuer.casc.pep;

import com.gstuer.casc.pep.predicate.PacketPredicate;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.function.Consumer;

public class NetworkBridge {
    private final PcapNetworkInterface networkInterfaceInsecure;
    private final PcapNetworkInterface networkInterfaceSecure;
    private final BlockingQueue<Packet> egressQueueInsecure;
    private final BlockingQueue<Packet> egressQueueSecure;
    private final PacketPredicate bypassPredicate;

    private EgressHandler egressHandlerInsecure;
    private EgressHandler egressHandlerSecure;
    private IngressHandler ingressHandlerInsecure;
    private IngressHandler ingressHandlerSecure;
    private ExecutorService threadPool;

    public NetworkBridge(PcapNetworkInterface networkInterfaceInsecure, PcapNetworkInterface networkInterfaceSecure, PacketPredicate... bypassPredicates) {
        this.networkInterfaceInsecure = Objects.requireNonNull(networkInterfaceInsecure);
        this.networkInterfaceSecure = Objects.requireNonNull(networkInterfaceSecure);
        this.egressQueueInsecure = new LinkedBlockingQueue<>();
        this.egressQueueSecure = new LinkedBlockingQueue<>();

        // Compose predicates for traffic bypass to single predicate
        PacketPredicate composedPredicate = PacketPredicate.getStaticPredicate(false);
        for (PacketPredicate bypassPredicate : bypassPredicates) {
            composedPredicate = composedPredicate.or(bypassPredicate);
        }
        this.bypassPredicate = composedPredicate;
    }

    public void open() {
        // If bridge is already open, ignore method call
        if ((this.egressHandlerInsecure != null || this.egressHandlerSecure != null
                || this.ingressHandlerInsecure != null || this.ingressHandlerSecure != null)
                && !this.threadPool.isTerminated()) {
            return;
        }

        // Clear egress queues of previously opened bridge
        this.egressQueueInsecure.clear();
        this.egressQueueSecure.clear();

        // Specify ingress packet consumers
        Consumer<Packet> egressEnqueueInsecure = this.egressQueueInsecure::offer;
        Consumer<Packet> egressEnqueueSecure = this.egressQueueSecure::offer;
        Consumer<Packet> packetConsumerInsecure = (packet) -> bypassPredicate.doIfMatches(packet, egressEnqueueSecure);
        Consumer<Packet> packetConsumerSecure = (packet) -> bypassPredicate.doIfMatches(packet, egressEnqueueInsecure);

        // Construct ingress and egress handlers
        try {
            this.egressHandlerInsecure = new EgressHandler(this.networkInterfaceInsecure, this.egressQueueInsecure);
            this.egressHandlerSecure = new EgressHandler(this.networkInterfaceSecure, this.egressQueueSecure);
            this.ingressHandlerInsecure = new IngressHandler(this.networkInterfaceInsecure, packetConsumerInsecure);
            this.ingressHandlerSecure = new IngressHandler(this.networkInterfaceSecure, packetConsumerSecure);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }

        // Start handler threads
        this.threadPool = Executors.newFixedThreadPool(4);
        this.threadPool.submit(egressHandlerInsecure::handle);
        this.threadPool.submit(egressHandlerSecure::handle);
        this.threadPool.submit(ingressHandlerInsecure::handle);
        this.threadPool.submit(ingressHandlerSecure::handle);
    }

    public void close() {
        this.ingressHandlerInsecure.close();
        this.ingressHandlerSecure.close();
        this.egressHandlerInsecure.close();
        this.egressHandlerSecure.close();
        this.threadPool.shutdownNow();
    }
}
