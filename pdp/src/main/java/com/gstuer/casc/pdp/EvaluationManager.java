package com.gstuer.casc.pdp;

import com.gstuer.casc.common.AccessDecision;
import com.gstuer.casc.common.AccessPolicy;
import com.gstuer.casc.common.attribute.AttributeSubscriber;
import com.gstuer.casc.common.pattern.AccessRequestPattern;

import java.time.Instant;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class EvaluationManager {
    private static final long FALLBACK_DENY_VALIDITY_MILLISECONDS = TimeUnit.SECONDS.toMillis(60);

    private final Set<PolicyEvaluator> policyEvaluators;
    private final AttributeSubscriber attributeSubscriber;

    public EvaluationManager(AttributeSubscriber attributeSubscriber) {
        this.policyEvaluators = new HashSet<>();
        this.attributeSubscriber = attributeSubscriber;
    }

    public AccessDecision getDecision(AccessRequestPattern pattern) {
        // Get most specific matching decisions for message
        Optional<AccessDecision> matchingDecision = this.policyEvaluators.parallelStream()
                .map(PolicyEvaluator::getDecision)
                .filter(decision -> pattern.contains(decision.getPattern()) && decision.isValid())
                .sorted()
                .findFirst();

        // Fallback to deny if no decision matches
        return matchingDecision.orElseGet(() -> new AccessDecision(pattern, AccessDecision.Action.DENY,
                null, Instant.now().plusMillis(FALLBACK_DENY_VALIDITY_MILLISECONDS)));
    }

    public void addPolicy(AccessPolicy policy) {
        // TODO Track subscribed attributes for removal of policies & associated attributes not required by other policies
        AccessRequestPattern pattern = policy.getFlowPattern();

        // Check if policy with same pattern was already added.
        Optional<PolicyEvaluator> conflictingEvaluator = this.policyEvaluators.parallelStream()
                .filter(evaluator -> pattern.equals(evaluator.getPolicy().getFlowPattern()))
                .findAny();
        if (conflictingEvaluator.isPresent()) {
            throw new IllegalArgumentException("Conflicting access policy was already added.");
        }

        // Create new policy evaluator and start its periodic evaluation.
        PolicyEvaluator policyEvaluator = new PolicyEvaluator(policy, this.attributeSubscriber);
        policyEvaluator.startPeriodicEvaluation();
        this.policyEvaluators.add(policyEvaluator);
    }
}
