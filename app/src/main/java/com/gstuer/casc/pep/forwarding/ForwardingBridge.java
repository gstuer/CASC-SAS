package com.gstuer.casc.pep.forwarding;

import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
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
    private final ExecutorService threadPool = Executors.newFixedThreadPool(2);

    private PcapHandle ingressHandle;
    private PcapHandle egressHandle;

    public ForwardingBridge(PcapNetworkInterface ingressInterface, PcapNetworkInterface egressInterface) {
        this.ingressInterface = Objects.requireNonNull(ingressInterface);
        this.egressInterface = Objects.requireNonNull(egressInterface);
        this.egressQueue = new LinkedBlockingQueue<>();
    }

    public void startForwarding() {
        // If forwarding is already in progress, ignore method call
        if (this.ingressHandle != null || this.egressHandle != null) {
            return;
        }

        // Construct packet capture handles for ingress & egress
        try {
            this.ingressHandle = buildIngressHandle(this.ingressInterface);
            this.egressHandle = buildEgressHandle(this.egressInterface);
        } catch (PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }

        // Clear egress queue of prior forwarding
        this.egressQueue.clear();

        // Start ingress and egress threads
        this.threadPool.submit(this::handleIngress);
        this.threadPool.submit(this::handleEgress);
    }

    public void stopForwarding() {
        this.ingressHandle.close();
        this.egressHandle.close();
        this.ingressHandle = null;
        this.egressHandle = null;
        this.threadPool.shutdownNow();
    }

    private void handleIngress() {
        UnfilteredForwardingListener listener = new UnfilteredForwardingListener(this.egressQueue);
        try {
            this.ingressHandle.loop(-1, listener);
        } catch (InterruptedException exception) {
            //No handling required: Interrupted via breakloop() method call
        } catch (NotOpenException | PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private void handleEgress() {
        while(this.egressHandle.isOpen()) {
            Packet packet;
            try {
                packet = this.egressQueue.take();
            } catch (InterruptedException exception) {
                break;
            }

            EthernetPacket.EthernetHeader header = (EthernetPacket.EthernetHeader) packet.getHeader();
            try {
                this.egressHandle.sendPacket(packet);
                // TODO Remove system.out call
                System.out.printf("%s -> %s: %s to %s\n", this.ingressInterface.getName(), this.egressInterface.getName(), header.getSrcAddr(), header.getDstAddr());
            } catch (NotOpenException | PcapNativeException exception) {
                throw new IllegalStateException(exception);
            }
        }
    }

    private static PcapHandle buildIngressHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return new PcapHandle.Builder(networkInterface.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .immediateMode(true)
                .direction(PcapHandle.PcapDirection.IN)
                .build();
    }

    private static PcapHandle buildEgressHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return new PcapHandle.Builder(networkInterface.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .immediateMode(true)
                .direction(PcapHandle.PcapDirection.OUT)
                .build();
    }
}
