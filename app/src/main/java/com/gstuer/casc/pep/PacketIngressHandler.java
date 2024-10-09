package com.gstuer.casc.pep;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.function.Consumer;

public class PacketIngressHandler extends IngressHandler<Packet> {
    private final PcapNetworkInterface ingressInterface;
    private final PcapHandle ingressHandle;

    public PacketIngressHandler(PcapNetworkInterface ingressInterface, PacketListener packetListener) throws PcapNativeException {
        this(ingressInterface, (Consumer<Packet>) packetListener::gotPacket);
    }

    public PacketIngressHandler(PcapNetworkInterface ingressInterface, Consumer<Packet> packetConsumer) throws PcapNativeException {
        super(packetConsumer);
        this.ingressInterface = Objects.requireNonNull(ingressInterface);
        this.ingressHandle = buildHandle(ingressInterface);
    }

    public void open() {
        try {
            // Handle packets until interrupted or exception is thrown
            this.ingressHandle.loop(-1, this::handle);
        } catch (InterruptedException exception) {
            //No handling required: e.g. interrupted via breakloop() method call
        } catch (NotOpenException | PcapNativeException exception) {
            throw new IllegalStateException(exception);
        }
        System.out.printf("[Ingress %s] Handler closed.\n", this.ingressInterface.getName());
    }

    public void close() {
        try {
            this.ingressHandle.breakLoop();
        } catch (NotOpenException exception) {
            // Ignore, ingress loop already stopped
        }
        this.ingressHandle.close();
    }

    protected PcapHandle buildHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return new PcapHandle.Builder(networkInterface.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .immediateMode(true)
                .direction(PcapHandle.PcapDirection.IN)
                .build();
    }
}
