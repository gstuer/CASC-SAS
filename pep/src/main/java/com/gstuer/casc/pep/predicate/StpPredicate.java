package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.util.Objects;

/**
 * Represents a {@link PacketPredicate packet predicate} to test for frames of the Spanning Tree Protocol (STP) over
 * IEEE 802.3 Ethernet.
 */
public class StpPredicate extends PacketPredicate {
    private static final short STP_ETHER_TYPE = (short) 0x0027;
    private static final MacAddress STP_DESTINATION_ADDRESS = MacAddress.getByName("01:80:c2:00:00:00");

    @Override
    public boolean test(Packet packet) {
        if (packet.contains(EthernetPacket.class)) {
            // TODO Evaluate how to deconstruct the 802.3 frame more precisely
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
            return Objects.equals(header.getType().value(), STP_ETHER_TYPE)
                    && header.getDstAddr().equals(STP_DESTINATION_ADDRESS);
        }
        return false;
    }
}