package com.gstuer.casc.common.attribute.predicate.numeric;

import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.UnavailableAttributeException;

import java.io.Serializable;
import java.util.Map;
import java.util.Set;

/**
 * A {@link PolicyPredicate predicate} mapping exactly one numeric {@link PolicyAttribute attribute} to a boolean value
 * using a {@link NumericOperator numeric operator}.
 *
 * @param <T> type of number expected as attribute value
 */
public class UnivariateNumericPredicate<T extends Number & Comparable<T>> extends PolicyPredicate implements Serializable {
    private final String identifier;
    private final NumericOperator<T> operator;
    private final T referenceValue;

    /**
     * Constructs a new {@link UnivariateNumericPredicate}.
     *
     * @param identifier     the identifier of the attribute to be queried
     * @param operator       the numeric operator to be applied on the attribute's actual value
     * @param referenceValue the value used as reference for the numeric operator
     */
    public UnivariateNumericPredicate(String identifier, NumericOperator<T> operator, T referenceValue) {
        this.identifier = identifier;
        this.operator = operator;
        this.referenceValue = referenceValue;
    }

    @Override
    @SuppressWarnings("unchecked")
    public Evaluation evaluate(Map<String, PolicyAttribute<?>> attributes) throws UnavailableAttributeException {
        PolicyAttribute<?> attribute = attributes.get(this.identifier);
        if (attribute != null) {
            T testValue;
            try {
                testValue = (T) attribute.getValue();
            } catch (ClassCastException exception) {
                throw new IllegalArgumentException("Attribute value has incompatible type for numeric predicate.");
            }
            boolean result = this.operator.test(this.referenceValue, testValue);
            return new Evaluation(result, attribute.getValidUntil());
        } else {
            throw new UnavailableAttributeException("Attribute with identifier \"" + this.identifier + "\"is unavailable.", null);
        }
    }

    @Override
    public Set<String> getRequiredAttributeIdentifiers() {
        return Set.of(identifier);
    }
}
