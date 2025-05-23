package com.gstuer.casc.common.attribute.predicate;

import com.gstuer.casc.common.attribute.PolicyAttribute;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Represents a function that maps a single or multiple {@link PolicyAttribute attributes} to a boolean value.
 */
public abstract class PolicyPredicate implements Predicate<Map<String, PolicyAttribute<?>>> {
    /**
     * Signals whether a set of non-flow-related system attributes satisfy this predicate.
     *
     * @param attributes a map of attributes indexed using their identifiers
     * @return {@code true} if the attributes satisfy the predicate, {@code false} otherwise.
     * @throws UnavailableAttributeException signals that the value of an attribute is unavailable and, thus, the
     *                                       evaluation of the predicate is not possible.
     */
    public abstract Evaluation evaluate(Map<String, PolicyAttribute<?>> attributes) throws UnavailableAttributeException;

    /**
     * Gets the identifiers of all {@link PolicyAttribute attributes} required for the evaluation of this predicate.
     *
     * @return the identifiers of all required {@link PolicyAttribute attributes}.
     */
    public abstract Set<String> getRequiredAttributeIdentifiers();

    @Override
    public boolean test(Map<String, PolicyAttribute<?>> attributes) {
        try {
            return this.evaluate(attributes).isPositive();
        } catch (UnavailableAttributeException exception) {
            return false;
        }
    }

    /**
     * Represents the result of the evaluation of a {@link PolicyPredicate policy predicate}.
     */
    public static final class Evaluation {
        private final boolean result;
        private final Instant endOfValidity;

        /**
         * Constructs a new {@link Evaluation}.
         *
         * @param result        the boolean result of a predicate evaluation.
         * @param endOfValidity the point in time until which the result is valid.
         */
        public Evaluation(boolean result, Instant endOfValidity) {
            this.result = result;
            this.endOfValidity = endOfValidity;
        }

        /**
         * Signals whether the evaluation of the predicate was positive.
         *
         * @return {@code true} if the evaluated predicate returned {@code true}, {@code false} otherwise.
         */
        public boolean isPositive() {
            return result;
        }

        /**
         * Gets the point in time until which the result of a predicate evaluation is valid.
         *
         * @return point in time until which the result is valid.
         */
        public Instant getEndOfValidity() {
            return endOfValidity;
        }
    }
}
