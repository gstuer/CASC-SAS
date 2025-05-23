package com.gstuer.casc.common.egress;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public class PacketEgressHandler extends EgressHandler<Packet> {
    private final PcapNetworkInterface egressInterface;
    private final PcapHandle egressHandle;

    public PacketEgressHandler(PcapNetworkInterface egressInterface, BlockingQueue<Packet> egressQueue) throws PcapNativeException {
        super(egressQueue);
        this.egressInterface = Objects.requireNonNull(egressInterface);
        this.egressHandle = buildHandle(egressInterface);
    }

    @Override
    public void open() {
        if (!this.egressHandle.isOpen()) {
            throw new IllegalStateException("Closed handler cannot be reopened.");
        }
        while (this.egressHandle.isOpen()) {
            Packet packet;
            try {
                packet = this.takeNextQueueItem();
            } catch (InterruptedException exception) {
                // Handler interrupted during waiting for new packet
                break;
            }
            this.handle(packet);
        }
        System.out.printf("[Egress %s] Handler closed.\n", this.egressInterface.getName());
    }

    @Override
    public void handle(Packet packet) {
        try {
            this.egressHandle.sendPacket(packet);
        } catch (NotOpenException | PcapNativeException exception) {
            // Throw no exception to continue sending after exception
            System.err.println(exception.getMessage());
        }
    }

    @Override
    public void close() {
        this.egressHandle.close();
    }

    protected PcapHandle buildHandle(PcapNetworkInterface networkInterface) throws PcapNativeException {
        return new PcapHandle.Builder(networkInterface.getName())
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .immediateMode(true)
                .direction(PcapHandle.PcapDirection.OUT)
                .build();
    }
}
