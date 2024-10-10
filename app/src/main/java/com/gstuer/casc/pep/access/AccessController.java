package com.gstuer.casc.pep.access;

import com.gstuer.casc.pep.access.cryptography.DigitalSignature;
import com.gstuer.casc.pep.access.cryptography.Signer;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public class AccessController {
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;
    private final BlockingQueue<Packet> packetEgress;
    private final AuthenticationManager authenticationManager;

    public AccessController(BlockingQueue<AccessControlMessage<?>> messageEgress, BlockingQueue<Packet> packetEgress) {
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.packetEgress = Objects.requireNonNull(packetEgress);
        this.authenticationManager = new AuthenticationManager(this.messageEgress);
    }

    public void handleOutgoingRequest(Packet packet) {
        // TODO Step 1: Exchange access control decision
        // TODO Step 2: Lookup address of destination PEP
        /* MAC Addresses
         * - Blueberry  (PEP 192.168.0.60) 00:e0:4c:68:02:40
         * - Blackberry (PEP 192.168.0.61) 00:e0:4c:68:02:69
         */
        InetAddress destination;
        EthernetPacket.EthernetHeader header = (EthernetPacket.EthernetHeader) packet.getHeader();
        if (header.getDstAddr().equals(MacAddress.getByName("00:e0:4c:68:02:40"))) {
            try {
                destination = InetAddress.getByName("192.168.0.60");
            } catch (UnknownHostException exception) {
                System.out.println("[AC] Error: " + exception.getMessage());
                return;
            }
        } else if (header.getDstAddr().equals(MacAddress.getByName("00:e0:4c:68:02:69"))) {
            try {
                destination = InetAddress.getByName("192.168.0.61");
            } catch (UnknownHostException exception) {
                System.out.println("[AC] Error: " + exception.getMessage());
                return;
            }
        } else {
            System.out.printf("[AC] Unknown destination %s.\n", header.getDstAddr());
            return;
        }

        // Step 3: Derive signature for packet
        Signer signer = this.authenticationManager.getSigner();
        DigitalSignature signature;
        try {
            signature = signer.sign(packet.getRawData());
        } catch (SignatureException | InvalidKeyException exception) {
            System.out.println("[AC] Error: " + exception.getMessage());
            return;
        }

        // Step 4: Wrap signature & packet in access request
        PayloadExchangeMessage payloadExchange = new PayloadExchangeMessage(destination, signature, packet);

        // Step 5: Queue access request for insecure egress
        this.messageEgress.offer(payloadExchange);
    }

    public void handleIncomingRequest(AccessControlMessage<?> accessControlMessage) {
        /* TODO Add handling of packets from insecure to secure network
         * Step 1: Verify signature
         * Step 2: Verify access control decision (access control decision lookup)
         * Step 3: Unwrap access request
         * Step 4: Queue encapsulated packet for secure egress
         */
        if (accessControlMessage instanceof PayloadExchangeMessage message) {
            Packet packet = message.getPayload();
            this.packetEgress.offer(packet);
        } else {
            System.out.println("Unknown message type.");
        }
    }
}
