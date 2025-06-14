package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Arrays;
import java.util.Objects;

/**
 * Represents a {@link PacketPredicate packet predicate} to test for supervision frames of the Parallel Redundancy
 * Protocol (PRP).
 */
public class PrpPredicate extends PacketPredicate {
    private static final short PRP_ETHER_TYPE = (short) 0x88fb;

    @Override
    public boolean test(Packet packet) {
        // Loop through packet in case of frame encapsulation
        while (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
            if (Objects.equals(header.getType().value(), (short) 0x8100)) {
                Dot1qVlanTagPacket vlanPacket = packet.get(Dot1qVlanTagPacket.class);
                Dot1qVlanTagPacket.Dot1qVlanTagHeader vlanHeader = vlanPacket.getHeader();
                if (Objects.equals(vlanHeader.getType().value(), PRP_ETHER_TYPE)) {
                    // Vlan ethernet frame is frame of searched type
                    return true;
                } else if (!Arrays.equals(ethernetPacket.getRawData(), packet.getRawData())) {
                    // Ethernet frame is encapsulated in another frame
                    packet = ethernetPacket;
                } else {
                    break;
                }
            } else if (Objects.equals(header.getType().value(), PRP_ETHER_TYPE)) {
                // Ethernet frame is frame of searched type
                return true;
            } else if (!Arrays.equals(ethernetPacket.getRawData(), packet.getRawData())) {
                // Ethernet frame is encapsulated in another frame
                packet = ethernetPacket;
            } else {
                break;
            }
        }
        // Captured packet does not contain frame of searched type
        return false;
    }
}
