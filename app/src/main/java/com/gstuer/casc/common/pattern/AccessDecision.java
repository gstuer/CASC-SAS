package com.gstuer.casc.common.pattern;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Objects;

/**
 * Represents an access decision taken by a policy decision point (PDP) and enforced by a policy enforcement point (PEP).
 */
public class AccessDecision implements Signable {
    private final AccessRequestPattern pattern;
    private final Decision decision;
    private final InetAddress nextHop;
    private final Instant validUntil;

    /**
     * Constructs a new {@link AccessDecision access decision}.
     *
     * @param pattern    the access request pattern this decision is valid for
     * @param decision   the decision taken for the access request pattern
     * @param nextHop    the address of an PEP to which a matching frame should be forwarded to
     * @param validUntil the point in time until the taken decision is valid
     */
    public AccessDecision(AccessRequestPattern pattern, Decision decision, InetAddress nextHop, Instant validUntil) {
        this.pattern = Objects.requireNonNull(pattern);
        this.decision = Objects.requireNonNull(decision);
        this.nextHop = Objects.requireNonNull(nextHop);
        this.validUntil = Objects.requireNonNull(validUntil);
    }

    /**
     * Gets the {@link AccessRequestPattern access request pattern} this decision is valid for.
     *
     * @return the access request pattern.
     */
    public AccessRequestPattern getPattern() {
        return pattern;
    }

    /**
     * Gets the {@link Decision decision} taken for the access request pattern.
     *
     * @return the decision.
     */
    public Decision getDecision() {
        return decision;
    }

    /**
     * Gets the address of an PEP to which a matching frame should be forwarded to.
     *
     * @return the next hop address.
     */
    public InetAddress getNextHop() {
        return nextHop;
    }

    /**
     * Gets the point in time until the taken decision is valid.
     *
     * @return the instant until the decision is valid.
     */
    public Instant getValidUntil() {
        return validUntil;
    }

    @Override
    public byte[] getSigningData() {
        byte[] patternBytes = this.pattern.getSigningData();
        byte[] decisionBytes = Ints.toByteArray(this.decision.ordinal());
        byte[] nextHopBytes = this.nextHop.getAddress();
        byte[] validUntilBytes = Longs.toByteArray(this.validUntil.toEpochMilli());
        return Bytes.concat(patternBytes, decisionBytes, nextHopBytes, validUntilBytes);
    }

    @Override
    public String toString() {
        try {
            return new JsonProcessor(true).convertToJson(this);
        } catch (SerializationException exception) {
            throw new IllegalStateException(exception);
        }
    }

    /**
     * Represents the result of a dynamic authorization of a policy decision point (PDP).
     */
    public enum Decision {
        /**
         * An access request is granted.
         */
        GRANTED,
        /**
         * An access request is denied.
         */
        DENIED;
    }
}
