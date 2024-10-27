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
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class AuthorizationController {
    private static final long FALLBACK_DENY_VALIDITY_MILLISECONDS = TimeUnit.SECONDS.toMillis(60);

    private final AuthenticationClient authenticationClient;
    private final Set<AccessDecision> accessDecisions;
    private final BlockingQueue<AccessControlMessage<?>> egressQueue;

    public AuthorizationController(BlockingQueue<AccessControlMessage<?>> egressQueue) {
        this.accessDecisions = ConcurrentHashMap.newKeySet();
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
            List<AccessDecision> matchingDecisions = this.accessDecisions.stream().parallel()
                    .filter(decision -> pattern.contains(decision.getPattern()) && decision.isValid())
                    .toList();

            // Fallback to deny if no decision fits
            if (matchingDecisions.isEmpty()) {
                AccessDecision decision = new AccessDecision(pattern, AccessDecision.Action.DENY,
                        null, Instant.now().plusMillis(FALLBACK_DENY_VALIDITY_MILLISECONDS));
                AccessDecisionMessage decisionMessage = new AccessDecisionMessage(message.getSource(), null, decision);
                authenticationClient.signMessage(decisionMessage).ifPresent(this.egressQueue::offer);
                System.out.println("[PDP] Deny: No match.");
                return;
            }

            // Check whether a specific deny decision exists
            // Note: A deny is "specific" if it contains all granted decision and is consequently the most specific match.
            List<AccessDecision> denyingDecisions = matchingDecisions.stream().parallel()
                    .filter(AccessDecision::isDenying).toList();
            List<AccessDecision> grantingDecisions = matchingDecisions.stream().parallel()
                    .filter(AccessDecision::isGranting).toList();
            if (!denyingDecisions.isEmpty()) {
                Optional<AccessDecision> specificDeny = denyingDecisions.stream().parallel()
                        .filter(deny -> grantingDecisions.stream().parallel()
                                .allMatch(grant -> deny.getPattern().contains(grant.getPattern())))
                        .findFirst();
                if (specificDeny.isPresent()) {
                    AccessDecisionMessage decisionMessage = new AccessDecisionMessage(message.getSource(), null, specificDeny.get());
                    authenticationClient.signMessage(decisionMessage).ifPresent(this.egressQueue::offer);
                    System.out.println("[PDP] Deny: Specific deny.");
                    return;
                }
            }

            // Return appropriate granting decision
            // TODO Make patterns comparable to reduce search effort for most specific deny/grant
            Optional<AccessDecision> grantingDecision = grantingDecisions.stream().findFirst();
            if (grantingDecision.isPresent()) {
                AccessDecisionMessage decisionMessageSource = new AccessDecisionMessage(message.getSource(), null, grantingDecision.get());
                AccessDecisionMessage decisionMessageDestination = new AccessDecisionMessage(grantingDecision.get().getNextHop(), null, grantingDecision.get());
                Optional<AccessControlMessage<?>> optionalMessageSource = authenticationClient.signMessage(decisionMessageSource);
                Optional<AccessControlMessage<?>> optionalMessageDestination = authenticationClient.signMessage(decisionMessageDestination);
                if (optionalMessageSource.isPresent() && optionalMessageDestination.isPresent()) {
                    this.egressQueue.offer(optionalMessageDestination.get());
                    this.egressQueue.offer(optionalMessageSource.get());
                    System.out.printf("[PDP] Grant: %s -> %s.\n", message.getSource(), grantingDecision.get().getNextHop());
                }
                return;
            }
        } else {
            System.out.println("[PDP] Unknown message type.");
        }
    }
}
