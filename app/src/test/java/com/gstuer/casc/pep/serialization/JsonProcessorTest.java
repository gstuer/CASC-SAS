package com.gstuer.casc.pep.serialization;

import com.gstuer.casc.pep.access.AccessControlMessage;
import com.gstuer.casc.pep.access.PayloadExchangeMessage;
import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class JsonProcessorTest {
    @Test
    public void testSerializationAndDeserializationOfPayloadExchangeMessage() throws UnknownHostException, SerializationException {
        // Test data
        JsonProcessor jsonProcessor = new JsonProcessor();
        InetAddress destination = InetAddress.getByName("localhost");
        Packet packet = new EthernetPacket.Builder()
                .srcAddr(MacAddress.getByName("00:00:00:00:00:00"))
                .dstAddr(MacAddress.getByName("ff:ff:ff:ff:ff:ff"))
                .type(EtherType.ARP)
                .paddingAtBuild(true)
                .build();
        DigitalSignature signature = new DigitalSignature(new byte[32], "test");
        PayloadExchangeMessage message = new PayloadExchangeMessage(destination, signature, packet);

        // Execution
        byte[] serialMessage = jsonProcessor.serialize(message);
        PayloadExchangeMessage deserialMessage = (PayloadExchangeMessage) jsonProcessor.deserialize(serialMessage, AccessControlMessage.class);

        // Assertion
        assertNotNull(deserialMessage);
        assertEquals(destination, message.getDestination());
        assertEquals(signature, deserialMessage.getSignature());
        assertEquals(packet.getHeader(), deserialMessage.getPayload().getHeader());
    }
}
