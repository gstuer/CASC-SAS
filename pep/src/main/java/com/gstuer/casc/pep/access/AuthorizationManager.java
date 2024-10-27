package com.gstuer.casc.pep.access;

import com.gstuer.casc.common.AuthenticationClient;
import com.gstuer.casc.common.concurrency.RequestableAccessDecision;
import com.gstuer.casc.common.concurrency.exception.RequestTimeoutException;
import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.message.AccessDecisionMessage;
import com.gstuer.casc.common.message.PayloadExchangeMessage;
import com.gstuer.casc.common.pattern.AccessDecision;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.PatternFactory;
import org.pcap4j.packet.Packet;

import java.net.InetAddress;
import java.util.Objects;
import java.util.Optional;
import java.util.SortedSet;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ConcurrentSkipListSet;

public class AuthorizationManager {
    private final InetAddress authorizationAuthority;
    private final InetAddress authorizationScope;
    private final AuthenticationClient authenticationClient;
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;
    private final ConcurrentMap<AccessRequestPattern, RequestableAccessDecision> requestedDecisions;
    private final SortedSet<AccessDecision> outgoingDecisions;
    private final SortedSet<AccessDecision> incomingDecisions;

    public AuthorizationManager(InetAddress authorizationAuthority,
                                InetAddress authorizationScope,
                                AuthenticationClient authenticationClient,
                                BlockingQueue<AccessControlMessage<?>> messageEgress) {
        this.authorizationAuthority = Objects.requireNonNull(authorizationAuthority);
        this.authorizationScope = Objects.requireNonNull(authorizationScope);
        this.authenticationClient = Objects.requireNonNull(authenticationClient);
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.requestedDecisions = new ConcurrentHashMap<>();
        this.outgoingDecisions = new ConcurrentSkipListSet<>();
        this.incomingDecisions = new ConcurrentSkipListSet<>();
    }

    public Optional<PayloadExchangeMessage> authorizeOutgoing(Packet packet) {
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(packet);
        Optional<AccessDecision> optionalDecision = this.outgoingDecisions.stream().parallel()
                .filter(decision -> pattern.contains(decision.getPattern()) && decision.isValid())
                .findFirst();

        if (optionalDecision.isPresent()) {
            AccessDecision decision = optionalDecision.get();
            if (decision.isGranting()) {
                // Access Granted -> Construct unsigned payload exchange message
                PayloadExchangeMessage message = new PayloadExchangeMessage(decision.getNextHop(), null, packet);
                return Optional.of(message);
            }
            // Access Denied -> Reject packet
            return Optional.empty();
        } else {
            // Request new decision from authorization authority
            RequestableAccessDecision requestableDecision = this.requestedDecisions.computeIfAbsent(pattern,
                    key -> new RequestableAccessDecision(this.messageEgress, this.authenticationClient.getSigner(),
                            authorizationAuthority, pattern));

            // Wait until decision is available
            AccessDecision decision;
            try {
                decision = requestableDecision.get();
            } catch (RequestTimeoutException exception) {
                return Optional.empty();
            }

            // If decision was positive return unsigned payload exchange message, return empty optional otherwise
            PayloadExchangeMessage message = null;
            if (decision.isGranting() && decision.isValid()) {
                message = new PayloadExchangeMessage(decision.getNextHop(), null, packet);
            }
            return Optional.ofNullable(message);
        }
    }

    public Optional<Packet> authorizeIncoming(PayloadExchangeMessage message) {
        // Reject empty payload exchange message
        if (!message.hasPayload()) {
            return Optional.empty();
        }

        // Check if pattern for message exists in incoming rules
        AccessRequestPattern pattern = PatternFactory.derivePatternFrom(message.getPayload());
        Optional<AccessDecision> optionalDecision = this.incomingDecisions.stream().parallel()
                .filter(decision -> pattern.contains(decision.getPattern())
                        && decision.isGranting() && decision.isValid())
                .findFirst();

        // Return payload if decision is present, return empty optional otherwise
        if (optionalDecision.isPresent()) {
            return Optional.of(message.getPayload());
        }
        return Optional.empty();
    }

    public void processMessage(AccessDecisionMessage message) {
        // Reject empty messages and messages which do not come from a policy decision point (authorization authority)
        if (!this.authenticationClient.verifyMessage(message) || !message.hasPayload()
                || !this.authorizationAuthority.equals(message.getSource())) {
            return;
        }

        // Add decision to either the outgoing or incoming rules
        AccessDecision decision = message.getPayload();
        if (authorizationScope.equals(decision.getNextHop())) {
            // If nextHop equals own scope, decision is still valid, & is granted -> Add to incoming rules
            if (decision.isGranting() && decision.isValid()) {
                // Only save granted decisions as incoming rules
                this.incomingDecisions.add(decision);
            }
        } else if (decision.isValid()) {
            // If nextHop does not equal own scope, add decision to outgoing rules and resolve possible waiting packets
            this.outgoingDecisions.add(decision);
            this.resolveRequests(decision);
        } else {
            // If nextHop does not equal own scope and decision is not valid (anymore), only resolve waiting packets
            this.resolveRequests(decision);
        }
    }

    private void resolveRequests(AccessDecision decision) {
        AccessRequestPattern pattern = decision.getPattern();
        requestedDecisions.entrySet().stream().parallel()
                .filter(entry -> entry.getValue().isUnavailable() && entry.getKey().contains(pattern))
                .forEach(entry -> {
                    entry.getValue().set(decision);
                    this.requestedDecisions.remove(entry.getKey());
                });
    }
}
