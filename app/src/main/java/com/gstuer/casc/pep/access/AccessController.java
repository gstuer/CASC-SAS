package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.Optional;
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

        // Step 3: Derive signature for packet & wrap with packet in access request
        Signer signer = this.authenticationManager.getSigner();
        PayloadExchangeMessage message = new PayloadExchangeMessage(destination, null, packet);
        Optional<AccessControlMessage<?>> signedMessage = this.authenticationManager.signMessage(message);

        // Step 4: Queue access request for insecure egress
        signedMessage.ifPresent(this.messageEgress::offer);
    }

    public void handleIncomingRequest(AccessControlMessage<?> accessControlMessage) {
        // TODO Add handling of packets from insecure to secure network
        // Step 1: Identify type of message
        if (accessControlMessage instanceof PayloadExchangeMessage message) {
            // Step 2: Verify signature
            if (!this.authenticationManager.verifyMessage(message)) {
                return;
            }

            // TODO Step 3: Verify access control decision (access control decision lookup)
            // Step 4: Queue encapsulated packet for secure egress
            this.packetEgress.offer(message.getPayload());
        } else if (accessControlMessage instanceof KeyExchangeMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationManager.processMessage(message);
        } else if (accessControlMessage instanceof KeyExchangeRequestMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationManager.processMessage(message);
        } else {
            System.out.println("[AC] Unknown message type.");
        }
    }
}
