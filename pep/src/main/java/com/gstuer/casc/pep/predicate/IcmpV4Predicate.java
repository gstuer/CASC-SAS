package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV4DestinationUnreachablePacket;
import org.pcap4j.packet.IcmpV4EchoPacket;
import org.pcap4j.packet.IcmpV4EchoReplyPacket;
import org.pcap4j.packet.IcmpV4InformationReplyPacket;
import org.pcap4j.packet.IcmpV4InformationRequestPacket;
import org.pcap4j.packet.IcmpV4ParameterProblemPacket;
import org.pcap4j.packet.IcmpV4RedirectPacket;
import org.pcap4j.packet.IcmpV4SourceQuenchPacket;
import org.pcap4j.packet.IcmpV4TimeExceededPacket;
import org.pcap4j.packet.IcmpV4TimestampPacket;
import org.pcap4j.packet.IcmpV4TimestampReplyPacket;
import org.pcap4j.packet.Packet;

/**
 * Represents a {@link PacketPredicate predicate} that evaluates if a {@link Packet packet} is an ICMPv4 packet.
 */
public class IcmpV4Predicate extends PacketPredicate {
    @Override
    public boolean test(Packet packet) {
        return packet.contains(IcmpV4CommonPacket.class)
                || packet.contains(IcmpV4EchoPacket.class) || packet.contains(IcmpV4EchoReplyPacket.class)
                || packet.contains(IcmpV4TimestampPacket.class) || packet.contains(IcmpV4TimestampReplyPacket.class)
                || packet.contains(IcmpV4InformationRequestPacket.class) || packet.contains(IcmpV4InformationReplyPacket.class)
                || packet.contains(IcmpV4DestinationUnreachablePacket.class) || packet.contains(IcmpV4ParameterProblemPacket.class)
                || packet.contains(IcmpV4RedirectPacket.class) || packet.contains(IcmpV4SourceQuenchPacket.class)
                || packet.contains(IcmpV4TimeExceededPacket.class);
    }
}
