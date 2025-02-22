package com.gstuer.casc.common.pattern;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.gstuer.casc.common.cryptography.Signable;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.net.InetAddress;
import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Objects;

/**
 * Represents an access decision taken by a policy decision point (PDP) and enforced by a policy enforcement point (PEP).
 */
public class AccessDecision implements Signable, Comparable<AccessDecision> {
    private final AccessRequestPattern pattern;
    private final Action action;
    private final InetAddress nextHop;
    private final Instant validUntil;

    /**
     * Constructs a new {@link AccessDecision access decision}.
     *
     * @param pattern    the access request pattern this decision is valid for
     * @param action     the action taken for the access request pattern
     * @param nextHop    the address of an PEP to which a matching frame should be forwarded to
     * @param validUntil the point in time until the taken decision is valid
     */
    public AccessDecision(AccessRequestPattern pattern, Action action, InetAddress nextHop, Instant validUntil) {
        this.pattern = Objects.requireNonNull(pattern);
        this.action = Objects.requireNonNull(action);
        this.nextHop = nextHop;
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
     * Gets the {@link Action action} to be taken for matching access request patterns.
     *
     * @return the action.
     */
    public Action getAction() {
        return action;
    }

    /**
     * Checks whether this access decision is granting matching {@link AccessRequestPattern patterns}.
     *
     * @return {@code true} if decision grants a matching pattern, {@code false} otherwise.
     */
    public boolean isGranting() {
        return this.action.equals(Action.GRANT);
    }

    /**
     * Checks whether this access decision is denying matching {@link AccessRequestPattern patterns}.
     *
     * @return {@code true} if decision denies a matching pattern, {@code false} otherwise.
     */
    public boolean isDenying() {
        return this.action.equals(Action.DENY);
    }

    /**
     * Gets the address of an PEP to which a matching frame should be forwarded to.
     *
     * @return the next hop address if this {@link #isGranting()}, {@code null} otherwise.
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

    /**
     * Checks whether this access decision is currently valid. An access decision is valid if the current instant is
     * within its validity period, i.e. before its expiration as indicated by {@link #getValidUntil()}.
     *
     * @return {@code true} if the decision is currently valid, {@code false} otherwise.
     */
    public boolean isValid() {
        return Instant.now().isBefore(this.validUntil);
    }

    /**
     * Checks whether this access decision is valid at a specified time in the future. An access decision is valid if
     * the current instant is within its validity period, i.e. before its expiration as indicated by
     * {@link #getValidUntil()}.
     *
     * @param temporalOffset the offset from {@link Instant#now()} specifying the time for which the validity is checked
     * @return {@code true} if the decision is valid at the specified time, {@code false} otherwise.
     */
    public boolean isValid(TemporalAmount temporalOffset) {
        return Instant.now().plus(temporalOffset).isBefore(this.validUntil);
    }

    @Override
    public byte[] getSigningData() {
        byte[] patternBytes = this.pattern.getSigningData();
        byte[] decisionBytes = Ints.toByteArray(this.action.ordinal());
        byte[] nextHopBytes = this.nextHop != null ? this.nextHop.getAddress() : new byte[0];
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

    @Override
    public boolean equals(Object object) {
        if (this == object) {
            return true;
        }
        if (object == null || getClass() != object.getClass()) {
            return false;
        }
        AccessDecision that = (AccessDecision) object;
        return Objects.equals(pattern, that.pattern)
                && action == that.action && Objects.equals(nextHop, that.nextHop)
                && Objects.equals(validUntil, that.validUntil);
    }

    @Override
    public int hashCode() {
        return Objects.hash(pattern, action, nextHop, validUntil);
    }

    @Override
    public int compareTo(AccessDecision that) {
        int patternComparison = this.getPattern().compareTo(that.getPattern());
        if (patternComparison != 0) {
            // Related but unequal patterns
            return patternComparison;
        } else {
            // Equal or unrelated patterns: Deny > Grant
            if (this.isGranting() && that.isDenying()) {
                return 1;
            } else if (this.isDenying() && that.isGranting()) {
                return -1;
            } else {
                // Same pattern, same action -> Fall back on hash values.
                return Integer.compare(this.hashCode(), that.hashCode());
            }
        }
    }

    /**
     * Represents the action of an {@link AccessDecision access decision}, which must be taken for matching
     * {@link AccessRequestPattern patterns} at a policy enforcement point (PEP).
     */
    public enum Action {
        /**
         * An access request must be granted.
         */
        GRANT,
        /**
         * An access request must be denied.
         */
        DENY;
    }
}
