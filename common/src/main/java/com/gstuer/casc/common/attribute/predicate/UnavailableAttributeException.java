package com.gstuer.casc.common.attribute.predicate;

/**
 * Signals that a {@link PolicyPredicate predicate} can not be evaluated due to an expected but missing attribute
 * value.
 */
public class UnavailableAttributeException extends Exception {
    /**
     * Constructs a new {@link UnavailableAttributeException}.
     *
     * @param message the detail message saved for later retrieval by the {@link #getMessage()} method.
     * @param cause   the cause saved for later retrieval by the {@link #getCause()} method. A null value is permitted
     *                and indicates that the cause is nonexistent or unknown.
     */
    public UnavailableAttributeException(String message, Throwable cause) {
        super(message, cause);
    }
}
