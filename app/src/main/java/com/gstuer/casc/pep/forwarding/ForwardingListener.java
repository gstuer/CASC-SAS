package com.gstuer.casc.pep.forwarding;

import org.pcap4j.core.PacketListener;
import org.pcap4j.packet.Packet;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public abstract class ForwardingListener implements PacketListener {
    private final BlockingQueue<Packet> forwardingQueue;

    protected ForwardingListener(BlockingQueue<Packet> forwardingQueue) {
        this.forwardingQueue = Objects.requireNonNull(forwardingQueue);
    }

    protected boolean enqueuePacket(Packet packet) {
        return forwardingQueue.offer(packet);
    }

    protected int getQueueSize() {
        return this.forwardingQueue.size();
    }
}
