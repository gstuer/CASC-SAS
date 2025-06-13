package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Objects;

/**
 * Represents a {@link PacketPredicate packet predicate} to test for frames of the Link Layer Discovery Protocol
 * (LLDP).
 */
public class LldpPredicate extends PacketPredicate {
    private static final short LLDP_ETHER_TYPE = (short) 0x88cc;

    @Override
    public boolean test(Packet packet) {
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
            return Objects.equals(header.getType().value(), LLDP_ETHER_TYPE);
        }
        return false;
    }
}
