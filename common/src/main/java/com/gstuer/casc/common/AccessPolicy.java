package com.gstuer.casc.common;

import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.net.InetAddress;
import java.util.Map;

/**
 * Represents an access control policy created by a policy administration point (PAP). A policy is used by a policy
 * decision point (PEP) to perform a dynamic authorization, i.e., to derive an {@link AccessDecision access decision}
 * for a given set of non-flow-related system {@link PolicyAttribute attributes}.
 */
public class AccessPolicy {
    private static final AccessDecision.Action DEFAULT_ACTION = AccessDecision.Action.DENY;
    private static final InetAddress DEFAULT_NEXT_HOP = null;

    private final AccessRequestPattern flowPattern;
    private final AccessDecision.Action action;
    private final InetAddress nextHop;
    private final PolicyPredicate predicate;

    /**
     * Constructs a new {@link AccessPolicy access policy}.
     *
     * @param flowPattern the access request pattern this policy is valid for
     * @param action      the action taken for access requests matching the flow pattern
     * @param nextHop     the address of an PEP to which a matching request has to be forwarded to
     * @param predicate   boolean function constraining any relevant non-flow-related system attributes
     */
    public AccessPolicy(AccessRequestPattern flowPattern, AccessDecision.Action action, InetAddress nextHop, PolicyPredicate predicate) {
        this.flowPattern = flowPattern;
        this.action = action;
        this.nextHop = nextHop;
        this.predicate = predicate;
    }

    /**
     * Derives an {@link AccessDecision access decision} from this {@link AccessPolicy access policy} for a given set of
     * non-flow-related system {@link PolicyAttribute attributes}.
     *
     * @param attributes a map of non-flow-related system attributes using their identifiers as map keys
     * @return an {@link AccessDecision access decision} derived from this {@link AccessPolicy access policy}.
     */
    public AccessDecision evaluate(Map<String, PolicyAttribute<?>> attributes) {
        PolicyPredicate.Evaluation evaluation = predicate.evaluate(attributes);
        if (evaluation.isPositive()) {
            return new AccessDecision(flowPattern, action, nextHop, evaluation.getEndOfValidity());
        } else {
            return new AccessDecision(flowPattern, DEFAULT_ACTION, DEFAULT_NEXT_HOP, evaluation.getEndOfValidity());
        }
    }
}
