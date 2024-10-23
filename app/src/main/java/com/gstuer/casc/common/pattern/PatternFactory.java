package com.gstuer.casc.common.pattern;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

/**
 * A utility class for the creation of {@link AccessRequestPattern pattern} instances.
 */
public final class PatternFactory {
    /**
     * Creates a {@link AccessRequestPattern pattern} from a {@link Packet packet}.
     *
     * @param packet the packet the pattern should be created for.
     * @return a pattern that represents the given packet.
     */
    public static AccessRequestPattern derivePatternFrom(Packet packet) {
        if (packet instanceof EthernetPacket ethernetPacket) {
            // Construct ethernet packet from ethernet frame
            EthernetPacket.EthernetHeader ethernetHeader = ethernetPacket.getHeader();
            EthernetPattern ethernetPattern = new EthernetPattern(ethernetHeader.getSrcAddr().toString(),
                    ethernetHeader.getDstAddr().toString(), ethernetHeader.getType().valueAsString());

            // Construct patterns for enclosed IPv4 packets
            if (ethernetPacket.getPayload() instanceof IpV4Packet ipV4Packet) {
                IpV4Packet.IpV4Header ipV4Header = ipV4Packet.getHeader();
                IPv4Pattern ipV4Pattern = new IPv4Pattern(ipV4Header.getSrcAddr().getHostAddress(),
                        ipV4Header.getDstAddr().getHostAddress(), ipV4Header.getProtocol().name(), ethernetPattern);

                // Construct patterns for enclosed TCP or UDP packets
                if (ipV4Packet.getPayload() instanceof UdpPacket udpPacket) {
                    UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();
                    return new UdpPattern(udpHeader.getSrcPort().valueAsInt(),
                            udpHeader.getDstPort().valueAsInt(), ipV4Pattern);
                } else if (ipV4Packet.getPayload() instanceof TcpPacket tcpPacket) {
                    TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
                    return new TcpPattern(tcpHeader.getSrcPort().valueAsInt(),
                            tcpHeader.getDstPort().valueAsInt(), ipV4Pattern);
                }
                return ipV4Pattern;
            }
            return ethernetPattern;
        } else {
            throw new IllegalArgumentException("Cannot derive pattern from unsupported packet type: "
                    + packet.getClass().getSimpleName());
        }
    }
}
