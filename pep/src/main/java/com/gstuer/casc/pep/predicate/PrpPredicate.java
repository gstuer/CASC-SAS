package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Objects;

/**
 * Represents a {@link PacketPredicate packet predicate} to test for supervision frames of the Parallel Redundancy
 * Protocol (PRP).
 */
public class PrpPredicate extends PacketPredicate {
    private static final short PRP_ETHER_TYPE = (short) 0x88fb;

    @Override
    public boolean test(Packet packet) {
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
            return Objects.equals(header.getType().value(), PRP_ETHER_TYPE);
        }
        return false;
    }
}
