package com.gstuer.casc.common.attribute.predicate.tree;

import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.time.InstantUtility;

import java.time.Instant;
import java.util.Map;

public class OrTree extends PredicateTree {
    public OrTree(PolicyPredicate leftChild, PolicyPredicate rightChild) {
        super(leftChild, rightChild);
    }

    @Override
    public Evaluation evaluate(Map<String, PolicyAttribute<?>> attributes) {
        // Evaluate child predicates
        Evaluation left = getLeftChild().evaluate(attributes);
        Evaluation right = getRightChild().evaluate(attributes);

        // Derive tree evaluation from children
        boolean result = left.isPositive() || right.isPositive();
        Instant endOfValidity;
        if (left.isPositive() && right.isPositive()) {
            // Both are positive, thus longer validity defines end of validity
            endOfValidity = InstantUtility.max(left.getEndOfValidity(), right.getEndOfValidity());
        } else if (left.isPositive()) {
            endOfValidity = left.getEndOfValidity();
        } else if (right.isPositive()) {
            endOfValidity = right.getEndOfValidity();
        } else {
            // Both are negative, thus earliest time for re-evaluation (min of times) defines end of validity
            endOfValidity = InstantUtility.min(left.getEndOfValidity(), right.getEndOfValidity());
        }
        return new Evaluation(result, endOfValidity);
    }
}
