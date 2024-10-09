package com.gstuer.casc.pep;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.function.Consumer;

public class PacketIngressHandler {
    private final PcapNetworkInterface ingressInterface;
    private final PcapHandle ingressHandle;
    private final PacketListener packetListener;

    public PacketIngressHandler(PcapNetworkInterface ingressInterface, PacketListener packetListener) throws PcapNativeException {
        this.ingressInterface = Objects.requireNonNull(ingressInterface);
        this.ingressHandle = buildHandle(ingressInterface);
        this.packetListener = Objects.requireNonNull(packetListener);
    }

    public PacketIngressHandler(PcapNetworkInterface ingressInterface, Consumer<Packet> packetConsumer) throws PcapNativeException {
        this(ingressInterface, createFromPacketConsumer(packetConsumer));
    }

    public void close() {
        try {
            this.ingressHandle.breakLoop();
        } catch (NotOpenException exception) {
            // Ignore, ingress loop already stopped
        }
        this.ingressHandle.close();
    }

    public void handle() {
        try {
            // Handle packets until interrupted or exception is thrown
            this.ingressHandle.loop(-1, this.packetListener);
        } catch (InterruptedException exception) {
            //No handling required: e.g. interrupted via breakloop() method call
        } catch (NotOpenException | PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }
        System.out.printf("[Ingress %s] Handler closed.\n", this.ingressInterface.getName());
    }

    private static PacketListener createFromPacketConsumer(Consumer<Packet> consumer) {
        return consumer::accept;
    }

    protected PcapHandle buildHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return new PcapHandle.Builder(networkInterface.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .immediateMode(true)
                .direction(PcapHandle.PcapDirection.IN)
                .build();
    }
}
