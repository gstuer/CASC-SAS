package com.gstuer.casc.pep;

import com.gstuer.casc.pep.forwarding.UnfilteredForwardingListener;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public class IngressHandler {
    private final PcapNetworkInterface ingressInterface;
    private final PcapHandle ingressHandle;
    private final BlockingQueue<Packet> egressQueue;

    public IngressHandler(PcapNetworkInterface ingressInterface, BlockingQueue<Packet> egressQueue) throws PcapNativeException {
        this.ingressInterface = Objects.requireNonNull(ingressInterface);
        this.ingressHandle = buildHandle(ingressInterface);
        this.egressQueue = Objects.requireNonNull(egressQueue);
    }

    public void handle() {
        this.handle(getPacketListener());
    }

    public void close() {
        try {
            this.ingressHandle.breakLoop();
        } catch (NotOpenException exception) {
            // Ignore, ingress loop already stopped
        }
        this.ingressHandle.close();
    }

    protected void handle(PacketListener packetListener) {
        try {
            // Handle packets until interrupted or exception is thrown
            this.ingressHandle.loop(-1, packetListener);
        } catch (InterruptedException exception) {
            //No handling required: e.g. interrupted via breakloop() method call
        } catch (NotOpenException | PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }
        System.out.printf("[Ingress %s] Handler closed.\n", this.ingressInterface.getName());
    }

    protected PcapHandle buildHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return new PcapHandle.Builder(networkInterface.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .immediateMode(true)
                .direction(PcapHandle.PcapDirection.IN)
                .build();
    }

    protected PacketListener getPacketListener() {
        return new UnfilteredForwardingListener(this.egressQueue);
    }
}
