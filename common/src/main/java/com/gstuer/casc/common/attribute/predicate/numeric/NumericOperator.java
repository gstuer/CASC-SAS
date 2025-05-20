package com.gstuer.casc.common.attribute.predicate.numeric;

import java.io.Serializable;
import java.util.function.BiPredicate;

/**
 * Represents a function mapping two numeric values ({@link Number} & {@link Comparable}) to a boolean output.
 *
 * @param <T> the type of number to be accepted as input
 */
public interface NumericOperator<T extends Number & Comparable<T>> extends Serializable, BiPredicate<T, T> {
    /**
     * Evaluates this operator for a given reference and test value.
     *
     * @param referenceValue value used as reference for the operator
     * @param testValue      value to be evaluated
     * @return {@code true} if the tested value satisfies the boolean operation in reference to the reference value,
     * {@code false} otherwise.
     */
    @Override
    boolean test(T referenceValue, T testValue);
}

