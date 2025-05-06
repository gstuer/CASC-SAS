package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.AccessRequestMessage;
import com.gstuer.casc.common.message.KeyExchangeMessage;
import com.gstuer.casc.common.message.KeyExchangeRequestMessage;
import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.util.Objects;
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

    public AuthorizationController(BlockingQueue<AccessControlMessage<?>> egressQueue,
                                   InetAddress authenticationAuthority, Authenticator<?, ?> authenticator) {
        this.accessDecisions = new ConcurrentSkipListSet<>();
        this.egressQueue = egressQueue;
        this.authenticationClient = new AuthenticationClient(authenticationAuthority, authenticator, this.egressQueue);

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
                    InetAddress.getByName("192.168.0.61"), Instant.now().plusSeconds(15));
            AccessDecision blackToBlueDecision = new AccessDecision(blackToBluePattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(15));
            this.accessDecisions.add(blueToBlackDecision);
            this.accessDecisions.add(blackToBlueDecision);
            new Thread(new DecisionRefresher(blueToBlackDecision, TimeUnit.SECONDS.toMillis(15))).start();
            new Thread(new DecisionRefresher(blackToBlueDecision, TimeUnit.SECONDS.toMillis(15))).start();
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }

        /* Rules for lab evaluation
        EthernetPattern blueToBlack1Pattern = new EthernetPattern(MacAddress.getByName("b4:b1:5a:1e:ef:b8"),
                MacAddress.getByName("01:15:4e:00:01:00"), new EtherType((short) 0x88fb, "PRP"));
        EthernetPattern blueToBlack2Pattern = new EthernetPattern(MacAddress.getByName("b4:b1:5a:1e:ef:b8"),
                MacAddress.getByName("01:80:c2:00:00:0e"), new EtherType((short) 0x88f7, "Unknown"));
        EthernetPattern blackToBlue1Pattern = new EthernetPattern(MacAddress.getByName("00:02:a3:e2:9d:c1"),
                MacAddress.getByName("01:15:4e:00:01:00"), new EtherType((short) 0x88fb, "PRP"));
        EthernetPattern blackToBlue2Pattern = new EthernetPattern(MacAddress.getByName("00:02:a3:e2:9d:c1"),
                MacAddress.getByName("01:0c:cd:01:01:02"), new EtherType((short) 0x8100, "VLAN Tagged Frame"));
        EthernetPattern blackToBlue3Pattern = new EthernetPattern(MacAddress.getByName("a0:b0:86:4e:d6:37"),
                MacAddress.getByName("01:80:c2:00:00:00"), new EtherType((short) 0x0027, "Unknown"));
        EthernetPattern blackToBlue4Pattern = new EthernetPattern(MacAddress.getByName("a0:b0:86:4e:d6:37"),
                MacAddress.getByName("01:80:c2:00:00:0e"), new EtherType((short) 0x88cc, "Unknown"));

        try {
            AccessDecision blueToBlackDecision1 = new AccessDecision(blueToBlack1Pattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), Instant.now().plusSeconds(10));
            AccessDecision blueToBlackDecision2 = new AccessDecision(blueToBlack2Pattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.61"), Instant.now().plusSeconds(10));
            AccessDecision blackToBlueDecision1 = new AccessDecision(blackToBlue1Pattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(10));
            AccessDecision blackToBlueDecision2 = new AccessDecision(blackToBlue2Pattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(10));
            AccessDecision blackToBlueDecision3 = new AccessDecision(blackToBlue3Pattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(10));
            AccessDecision blackToBlueDecision4 = new AccessDecision(blackToBlue4Pattern, AccessDecision.Action.GRANT,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(10));
            this.accessDecisions.add(blueToBlackDecision1);
            this.accessDecisions.add(blueToBlackDecision2);
            this.accessDecisions.add(blackToBlueDecision1);
            this.accessDecisions.add(blackToBlueDecision2);
            this.accessDecisions.add(blackToBlueDecision3);
            this.accessDecisions.add(blackToBlueDecision4);
            new Thread(new DecisionRefresher(blueToBlackDecision1, TimeUnit.SECONDS.toMillis(10))).start();
            new Thread(new DecisionRefresher(blueToBlackDecision2, TimeUnit.SECONDS.toMillis(10))).start();
            new Thread(new DecisionRefresher(blackToBlueDecision1, TimeUnit.SECONDS.toMillis(10))).start();
            new Thread(new DecisionRefresher(blackToBlueDecision2, TimeUnit.SECONDS.toMillis(10))).start();
            new Thread(new DecisionRefresher(blackToBlueDecision3, TimeUnit.SECONDS.toMillis(10))).start();
            new Thread(new DecisionRefresher(blackToBlueDecision4, TimeUnit.SECONDS.toMillis(10))).start();
        } catch (UnknownHostException exception) {
            throw new IllegalStateException(exception);
        }
        */
    }

    public void handleRequest(AccessControlMessage<?> accessControlMessage) {
        long arrivalTime = System.nanoTime();
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
                System.out.printf("[PDP] Grant: %s -> %s. (took %d ms)\n", message.getSource(), decision.getNextHop(), TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - arrivalTime));

            } else {
                System.out.println("[PDP] Signing failed.");
                return;
            }
        } else {
            System.out.println("[PDP] Unknown message type.");
        }
    }

    private final class DecisionRefresher implements Runnable {
        private final static long REFRESH_THRESHOLD = 50;
        private final static long SLEEP_OFFSET = 30;
        private final long validityMilliseconds;
        private AccessDecision decision;

        private DecisionRefresher(AccessDecision decision, long validityMilliseconds) {
            this.decision = Objects.requireNonNull(decision);
            this.validityMilliseconds = validityMilliseconds;
        }

        @Override
        public void run() {
            System.out.println("[PDP] Starting refresh thread.");
            while (true) {
                long timeLeft = Instant.now().until(decision.getValidUntil(), TimeUnit.MILLISECONDS.toChronoUnit());
                if (timeLeft < REFRESH_THRESHOLD) {
                    AccessDecision renewDecision = new AccessDecision(decision.getPattern(), decision.getAction(),
                            decision.getNextHop(), Instant.now().plusMillis(this.validityMilliseconds));
                    AuthorizationController.this.accessDecisions.remove(this.decision);
                    AuthorizationController.this.accessDecisions.add(renewDecision);
                    this.decision = renewDecision;
                    continue;
                }
                try {
                    Thread.sleep(timeLeft - SLEEP_OFFSET);
                } catch (InterruptedException exception) {
                    break;
                }
            }
        }
    }
}
