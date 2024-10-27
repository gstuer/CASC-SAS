package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.pattern.AccessDecision;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Optional;
import java.util.SortedSet;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.TimeUnit;

public class AuthorizationController {
    private static final long FALLBACK_DENY_VALIDITY_MILLISECONDS = TimeUnit.SECONDS.toMillis(60);

    private final AuthenticationClient authenticationClient;
    private final SortedSet<AccessDecision> accessDecisions;
    private final BlockingQueue<AccessControlMessage<?>> egressQueue;

    public AuthorizationController(BlockingQueue<AccessControlMessage<?>> egressQueue) {
        this.accessDecisions = new ConcurrentSkipListSet<>();
        this.egressQueue = egressQueue;
        this.authenticationClient = new AuthenticationClient(this.egressQueue);

        // TODO Remove static rules
        /* MAC Addresses
         * - Blueberry  (PEP 192.168.0.60) 00:e0:4c:68:02:40
         * - Blackberry (PEP 192.168.0.61) 00:e0:4c:68:02:69
         */
        EthernetPattern blueToBlackPattern = new EthernetPattern(MacAddress.getByName("00:e0:4c:68:02:40"),
                MacAddress.getByName("00:e0:4c:68:02:69"), EtherType.IPV4);
        EthernetPattern blackToBluePattern = new EthernetPattern(MacAddress.getByName("00:e0:4c:68:02:69"),
                MacAddress.getByName("00:e0:4c:68:02:40"), EtherType.IPV4);

        try {
            AccessDecision blueToBlackDecision = new AccessDecision(blueToBlackPattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), Instant.now().plusSeconds(60));
            AccessDecision blackToBlueDecision = new AccessDecision(blackToBluePattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(60));
            this.accessDecisions.add(blueToBlackDecision);
            this.accessDecisions.add(blackToBlueDecision);
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
    }

    public void handleRequest(AccessControlMessage<?> accessControlMessage) {
        // Identify type of message
        if (accessControlMessage instanceof KeyExchangeMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationClient.processMessage(message);
        } else if (accessControlMessage instanceof KeyExchangeRequestMessage message) {
            // Forward message to authentication manager for processing
            this.authenticationClient.processMessage(message);
        } else if (accessControlMessage instanceof AccessRequestMessage message) {
            // Verify signature
            if (!this.authenticationClient.verifyMessage(message)) {
                return;
            }

            // Get matching decisions for message
            AccessRequestPattern pattern = message.getPayload();
            Optional<AccessDecision> optionalMatchingDecision = this.accessDecisions.stream().parallel()
                    .filter(decision -> pattern.contains(decision.getPattern()) && decision.isValid()).findFirst();

            // Fallback to deny if no decision fits
            if (optionalMatchingDecision.isEmpty()) {
                AccessDecision decision = new AccessDecision(pattern, AccessDecision.Action.DENY,
                        null, Instant.now().plusMillis(FALLBACK_DENY_VALIDITY_MILLISECONDS));
                AccessDecisionMessage decisionMessage = new AccessDecisionMessage(message.getSource(), null, decision);
                authenticationClient.signMessage(decisionMessage).ifPresent(this.egressQueue::offer);
                System.out.println("[PDP] Deny: No match.");
                return;
            }

            AccessDecision decision = optionalMatchingDecision.get();
            // Send decision to next hop if granted
            if (decision.isGranting()) {
                AccessDecisionMessage decisionMessage = new AccessDecisionMessage(decision.getNextHop(), null, decision);
                Optional<AccessControlMessage<?>> optionalDecisionMessage = authenticationClient.signMessage(decisionMessage);
                if (optionalDecisionMessage.isPresent()) {
                    this.egressQueue.offer(optionalDecisionMessage.get());
                } else {
                    System.out.println("[PDP] Signing failed.");
                    return;
                }
            }

            // Send decision to requester
            AccessDecisionMessage decisionMessage = new AccessDecisionMessage(message.getSource(), null, decision);
            Optional<AccessControlMessage<?>> optionalDecisionMessage = authenticationClient.signMessage(decisionMessage);
            if (optionalDecisionMessage.isPresent()) {
                this.egressQueue.offer(optionalDecisionMessage.get());
                System.out.printf("[PDP] Grant: %s -> %s.\n", message.getSource(), decision.getNextHop());
            } else {
                System.out.println("[PDP] Signing failed.");
                return;
            }
        } else {
            System.out.println("[PDP] Unknown message type.");
        }
    }
}
