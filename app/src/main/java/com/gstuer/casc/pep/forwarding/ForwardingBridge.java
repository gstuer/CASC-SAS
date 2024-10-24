package com.gstuer.casc.pep.forwarding;

import com.gstuer.casc.common.egress.PacketEgressHandler;
import com.gstuer.casc.common.ingress.PacketIngressHandler;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class ForwardingBridge {
    private final PcapNetworkInterface ingressInterface;
    private final PcapNetworkInterface egressInterface;
    private final BlockingQueue<Packet> egressQueue;

    private PacketIngressHandler ingressHandler;
    private PacketEgressHandler egressHandler;
    private ExecutorService threadPool;

    public ForwardingBridge(PcapNetworkInterface ingressInterface, PcapNetworkInterface egressInterface) {
        this.ingressInterface = Objects.requireNonNull(ingressInterface);
        this.egressInterface = Objects.requireNonNull(egressInterface);
        this.egressQueue = new LinkedBlockingQueue<>();
    }

    public void startForwarding() {
        // If forwarding is already in progress, ignore method call
        if (ingressHandler != null && egressHandler != null && !this.threadPool.isTerminated()) {
            return;
        }

        // Construct packet capture handlers for ingress & egress
        try {
            ingressHandler = new PacketIngressHandler(this.ingressInterface, new UnfilteredForwardingListener(this.egressQueue));
            egressHandler = new PacketEgressHandler(this.egressInterface, this.egressQueue);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }

        // Clear egress queue of prior forwarding
        this.egressQueue.clear();

        // Start ingress and egress threads
        threadPool = Executors.newFixedThreadPool(2);
        this.threadPool.submit(egressHandler::open);
        this.threadPool.submit(ingressHandler::open);
    }

    public void stopForwarding() {
        this.ingressHandler.close();
        this.egressHandler.close();
        this.threadPool.shutdownNow();
    }
}
