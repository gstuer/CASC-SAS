package com.gstuer.casc.pep.serialization;

import com.gstuer.casc.common.cryptography.DigitalSignature;
import com.gstuer.casc.common.cryptography.EncodedKey;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import com.gstuer.casc.common.pattern.AccessDecision;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import com.gstuer.casc.common.pattern.IPv4Pattern;
import com.gstuer.casc.common.pattern.PatternFactory;
import com.gstuer.casc.common.pattern.UdpPattern;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpV4TosPrecedence;
import org.pcap4j.packet.namednumber.IpV4TosTos;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.pcap4j.util.MacAddress;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

public class JsonProcessorTest {
    @Test
    public void testSerializationAndDeserializationOfPayloadExchangeMessage() throws UnknownHostException, SerializationException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        Packet packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.ARP)
                .paddingAtBuild(true)
                .build();
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        PayloadExchangeMessage message = new PayloadExchangeMessage(source, destination, signature, packet);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        PayloadExchangeMessage deserialMessage = (PayloadExchangeMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(source, message.getSource());
        assertEquals(destination, message.getDestination());
        assertEquals(signature, deserialMessage.getSignature());
        assertEquals(packet.getHeader(), deserialMessage.getPayload().getHeader());
    }

    @Test
    public void testSerializationAndDeserializationOfKeyExchangeRequestMessageWithSignature() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        String algorithmIdentifier = "ALGORITHM";
        KeyExchangeRequestMessage message = new KeyExchangeRequestMessage(source, destination, signature, algorithmIdentifier);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        KeyExchangeRequestMessage deserialMessage = (KeyExchangeRequestMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(source, message.getSource());
        assertEquals(destination, message.getDestination());
        assertEquals(signature, deserialMessage.getSignature());
        assertEquals(algorithmIdentifier, deserialMessage.getPayload());
    }

    @Test
    public void testSerializationAndDeserializationOfKeyExchangeRequestMessageWithoutSignature() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        String algorithmIdentifier = "ALGORITHM";
        KeyExchangeRequestMessage message = new KeyExchangeRequestMessage(source, destination, null, algorithmIdentifier);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        KeyExchangeRequestMessage deserialMessage = (KeyExchangeRequestMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(source, message.getSource());
        assertEquals(destination, message.getDestination());
        assertNull(deserialMessage.getSignature());
        assertEquals(algorithmIdentifier, deserialMessage.getPayload());
    }

    @Test
    public void testSerializationAndDeserializationOfKeyExchangeMessage() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress source = InetAddress.getByName("127.0.0.1");
        InetAddress destination = InetAddress.getByName("localhost");
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        EncodedKey encodedKey = new EncodedKey("ALGORITHM", new byte[32]);
        KeyExchangeMessage message = new KeyExchangeMessage(source, destination, signature, encodedKey);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        KeyExchangeMessage deserialMessage = (KeyExchangeMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(source, message.getSource());
        assertEquals(destination, message.getDestination());
        assertEquals(signature, deserialMessage.getSignature());
        assertEquals(encodedKey, deserialMessage.getPayload());
    }

    @Test
    public void testSerializationAndDeserializationOfAccessRequestPattern() throws UnknownHostException, SerializationException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        EthernetPacket packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.IPV4)
                .paddingAtBuild(true)
                .payloadBuilder(new IpV4Packet.Builder()
                        .version(IpVersion.IPV4)
                        .tos(new IpV4Rfc1349Tos.Builder()
                                .precedence(IpV4TosPrecedence.ROUTINE)
                                .tos(IpV4TosTos.DEFAULT)
                                .build())
                        .srcAddr((Inet4Address) Inet4Address.getByName("192.168.0.50"))
                        .dstAddr((Inet4Address) Inet4Address.getByName("192.168.0.51"))
                        .protocol(IpNumber.UDP)
                        .payloadBuilder(new UdpPacket.Builder()
                                .srcAddr(Inet4Address.getByName("192.168.0.50"))
                                .srcPort(new UdpPort((short) 10001, "SABAAC"))
                                .dstAddr(Inet4Address.getByName("192.168.0.51"))
                                .dstPort(new UdpPort((short) 10000, "SABAAC"))
                        ))
                .build();

        // Execution
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(packet);
        byte[] serialPattern = jsonProcessor.serialize(pattern);
        UdpPattern udpPattern = (UdpPattern) jsonProcessor.deserialize(serialPattern, AccessRequestPattern.class);
        IPv4Pattern ipPattern = (IPv4Pattern) udpPattern.getEnclosedPattern();
        EthernetPattern ethernetPattern = (EthernetPattern) ipPattern.getEnclosedPattern();

        // Assertion
        assertEquals(packet.getHeader().getSrcAddr().toString(), ethernetPattern.getSource());
        assertEquals(packet.getHeader().getDstAddr().toString(), ethernetPattern.getDestination());
        assertEquals(packet.getHeader().getType().valueAsString(), ethernetPattern.getEtherType());
        assertFalse(ethernetPattern.hasEnclosedPattern());
        assertNull(ethernetPattern.getEnclosedPattern());

        IpV4Packet ipPacket = (IpV4Packet) packet.getPayload();
        assertEquals(ipPacket.getHeader().getSrcAddr().getHostAddress(), ipPattern.getSource());
        assertEquals(ipPacket.getHeader().getDstAddr().getHostAddress(), ipPattern.getDestination());
        assertEquals(ipPacket.getHeader().getProtocol().name(), ipPattern.getProtocol());

        UdpPacket udpPacket = (UdpPacket) ipPacket.getPayload();
        assertEquals(udpPacket.getHeader().getSrcPort().valueAsInt(), udpPattern.getSourcePort());
        assertEquals(udpPacket.getHeader().getDstPort().valueAsInt(), udpPattern.getDestinationPort());
    }

    @Test
    public void testSerializationAndDeserializationOfAccessDecision() throws SerializationException, UnknownHostException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessRequestPattern pattern = new UdpPattern(10000, 10001, null);
        InetAddress address = InetAddress.getByName("127.0.0.1");
        AccessDecision.Decision decision = AccessDecision.Decision.GRANTED;
        Instant validUntilNow = Instant.now();
        AccessDecision accessDecision = new AccessDecision(pattern, decision, address, validUntilNow);

        // Execution
        byte[] serial = jsonProcessor.serialize(accessDecision);
        AccessDecision deserialized = jsonProcessor.deserialize(serial, AccessDecision.class);

        // Assertion
        assertNotNull(deserialized);
        assertEquals(pattern, deserialized.getPattern());
        assertEquals(address, deserialized.getNextHop());
        assertEquals(decision, deserialized.getDecision());
        assertEquals(validUntilNow, deserialized.getValidUntil());
    }
}
