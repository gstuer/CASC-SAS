package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

/**
 * Represents a {@link PacketPredicate predicate} that evaluates if a {@link Packet packet} is an ARP packet.
 */
public class ArpPredicate extends PacketPredicate {
    @Override
    public boolean test(Packet packet) {
        return packet.contains(ArpPacket.class);
    }
}
