package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.Dot1qVlanTagPacket;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;

import java.util.Arrays;
import java.util.Objects;

public class SampledValuesPredicate extends PacketPredicate {
    @Override
    public boolean test(Packet packet) {
        // Loop through packet in case of frame encapsulation
        while (packet.contains(EthernetPacket.class)) {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            EthernetPacket.EthernetHeader header = ethernetPacket.getHeader();
            if (Objects.equals(header.getType().value(), (short) 0x8100)) {
                Dot1qVlanTagPacket vlanPacket = packet.get(Dot1qVlanTagPacket.class);
                Dot1qVlanTagPacket.Dot1qVlanTagHeader vlanHeader = vlanPacket.getHeader();
                if (Objects.equals(vlanHeader.getType().value(), (short) 0x88BA)) {
                    // Vlan ethernet frame is sampled values frame
                    return true;
                } else if (!Arrays.equals(ethernetPacket.getRawData(), packet.getRawData())) {
                    // Ethernet frame is encapsulated in another frame
                    packet = ethernetPacket;
                } else {
                    break;
                }
            } else if (Objects.equals(header.getType().value(), (short) 0x88BA)) {
                // Ethernet frame is sampled values frame
                return true;
            } else if (!Arrays.equals(ethernetPacket.getRawData(), packet.getRawData())) {
                // Ethernet frame is encapsulated in another frame
                packet = ethernetPacket;
            } else {
                break;
            }
        }
        // Captured packet does not contain sampled values frame
        return false;
    }
}
