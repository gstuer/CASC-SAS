package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.namednumber.TcpPort;

/**
 * Represents a {@link PacketPredicate predicate} that evaluates if a {@link Packet packet} is an SSH packet sent over
 * TCP.
 */
public class SshOverTcpPredicate extends PacketPredicate {
    @Override
    public boolean test(Packet packet) {
        return packet.contains(TcpPacket.class)
                && (packet.get(TcpPacket.class).getHeader().getDstPort().equals(TcpPort.SSH)
                || packet.get(TcpPacket.class).getHeader().getSrcPort().equals(TcpPort.SSH));
    }
}
