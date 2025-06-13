package com.gstuer.casc.common.attribute.predicate;

import com.gstuer.casc.common.attribute.AttributeIdentifier;
import com.gstuer.casc.common.attribute.PolicyAttribute;

import java.time.Instant;
import java.time.temporal.TemporalAmount;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public class StaticResultPredicate extends PolicyPredicate {
    private final boolean result;
    private final TemporalAmount evaluationValidity;

    public StaticResultPredicate(boolean result, TemporalAmount evaluationValidity) {
        this.result = result;
        this.evaluationValidity = Objects.requireNonNull(evaluationValidity);
    }

    @Override
    public Evaluation evaluate(Map<AttributeIdentifier, PolicyAttribute<?>> attributes) throws UnavailableAttributeException {
        return new Evaluation(result, Instant.now().plus(evaluationValidity));
    }

    @Override
    public Set<AttributeIdentifier> getRequiredAttributeIdentifiers() {
        return Set.of();
    }
}
