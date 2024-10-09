package com.gstuer.casc.pep.serialization;

import com.gstuer.casc.pep.access.AccessControlMessage;
import com.gstuer.casc.pep.access.KeyExchangeMessage;
import com.gstuer.casc.pep.access.KeyExchangeRequestMessage;
import com.gstuer.casc.pep.access.PayloadExchangeMessage;
import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.access.cryptography.EncodedKey;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;

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
}
