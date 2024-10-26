package com.gstuer.casc.pep.forwarding;

import org.pcap4j.packet.Packet;

import java.util.concurrent.BlockingQueue;

public class UnfilteredForwardingListener extends ForwardingListener {
    public UnfilteredForwardingListener(BlockingQueue<Packet> forwardingQueue) {
        super(forwardingQueue);
    }

    @Override
    public void gotPacket(Packet packet) {
        this.enqueuePacket(packet);
    }
}
