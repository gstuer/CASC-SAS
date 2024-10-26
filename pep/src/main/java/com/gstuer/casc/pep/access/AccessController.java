package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.BlockingQueue;

public class AccessController {
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;
    private final BlockingQueue<Packet> packetEgress;
    private final AuthenticationManager authenticationManager;
    private final AuthorizationManager authorizationManager;

    public AccessController(BlockingQueue<AccessControlMessage<?>> messageEgress, BlockingQueue<Packet> packetEgress,
                            InetAddress authorizationAuthority, InetAddress authorizationScope) {
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.packetEgress = Objects.requireNonNull(packetEgress);
        this.authenticationManager = new AuthenticationManager(this.messageEgress);
        this.authorizationManager = new AuthorizationManager(authorizationAuthority, authorizationScope,
                this.authenticationManager, this.messageEgress);
    }

    public void handleOutgoingRequest(Packet packet) {
        // Step 1: Check authorization for outgoing packet
        Optional<PayloadExchangeMessage> optionalMessage = this.authorizationManager.authorizeOutgoing(packet);
        if (optionalMessage.isEmpty()) {
            System.out.println("[AC] Unauthorized outgoing packet: " + packet.getHeader());
            return;
        }

        // Step 2: Derive signature for payload exchange message
        Optional<AccessControlMessage<?>> signedMessage = this.authenticationManager.signMessage(optionalMessage.get());

        // Step 3: Queue access request for insecure egress
        signedMessage.ifPresent(this.messageEgress::offer);
    }

    public void handleIncomingRequest(AccessControlMessage<?> accessControlMessage) {
        // Step 1: Identify type of message
        if (accessControlMessage instanceof PayloadExchangeMessage message) {
            // Step 2: Verify signature
            if (!this.authenticationManager.verifyMessage(message)) {
                return;
            }

            // Step 3: Verify access control decision (access control decision lookup)
            Optional<Packet> optionalPacket = this.authorizationManager.authorizeIncoming(message);
            if (optionalPacket.isEmpty()) {
                System.out.println("[AC] Unauthorized incoming packet: " + message.getPayload().getHeader());
                return;
            }

            // Step 4: Queue encapsulated packet for secure egress
            this.packetEgress.offer(optionalPacket.get());
        } else if (accessControlMessage instanceof KeyExchangeMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationManager.processMessage(message);
        } else if (accessControlMessage instanceof KeyExchangeRequestMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationManager.processMessage(message);
        } else if (accessControlMessage instanceof AccessDecisionMessage message) {
            // Forward message to authorization manager for processing
            this.authorizationManager.processMessage(message);
        } else {
            System.out.println("[AC] Unknown message type.");
        }
    }
}
