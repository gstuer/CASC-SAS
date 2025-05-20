package com.gstuer.casc.common.attribute.predicate;

import com.gstuer.casc.common.attribute.PolicyAttribute;

import java.time.Instant;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Represents a function
 */
public abstract class PolicyPredicate implements Predicate<Map<String, PolicyAttribute<?>>> {
    public abstract Evaluation evaluate(Map<String, PolicyAttribute<?>> attributes) throws UnavailableAttributeException;

    @Override
    public boolean test(Map<String, PolicyAttribute<?>> attributes) {
        try {
            return this.evaluate(attributes).isPositive();
        } catch (UnavailableAttributeException exception) {
            return false;
        }
    }

    public static final class Evaluation {
        private final boolean result;
        private final Instant endOfValidity;

        public Evaluation(boolean result, Instant endOfValidity) {
            this.result = result;
            this.endOfValidity = endOfValidity;
        }

        public boolean isPositive() {
            return result;
        }

        public Instant getEndOfValidity() {
            return endOfValidity;
        }
    }
}
