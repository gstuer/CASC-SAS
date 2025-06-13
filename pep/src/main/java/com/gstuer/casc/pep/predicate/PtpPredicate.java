package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Objects;

/**
 * Represents a {@link PacketPredicate packet predicate} to test for frames of the Precision Time Protocol (PTP) over
 * IEEE 802.3 Ethernet.
 */
public class PtpPredicate extends PacketPredicate {
    private static final short PTP_ETHER_TYPE = (short) 0x88f7;

    @Override
    public boolean test(Packet packet) {
        if (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
            return Objects.equals(header.getType().value(), PTP_ETHER_TYPE);
        }
        return false;
    }
}
