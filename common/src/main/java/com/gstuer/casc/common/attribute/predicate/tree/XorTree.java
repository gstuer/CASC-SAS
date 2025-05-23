package com.gstuer.casc.common.attribute.predicate.tree;

import com.gstuer.casc.common.attribute.PolicyAttribute;
import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;
import com.gstuer.casc.common.attribute.predicate.UnavailableAttributeException;
import com.gstuer.casc.common.time.InstantUtility;

import java.time.Instant;
import java.util.Map;

/**
 * Represents a {@link PredicateTree tree of predicates} that uses the logical XOR-operator to evaluate its underlying
 * {@link PolicyPredicate policy predicates}.
 */
public class XorTree extends PredicateTree {
    /**
     * Constructs a new {@link XorTree}.
     *
     * @param leftChild  first child node of the tree
     * @param rightChild second child node of the tree
     */
    public XorTree(PolicyPredicate leftChild, PolicyPredicate rightChild) {
        super(leftChild, rightChild);
    }

    @Override
    public Evaluation evaluate(Map<String, PolicyAttribute<?>> attributes) throws UnavailableAttributeException {
        // Evaluate child predicates
        // TODO Only throw unavail. attr. except. if neither left nor right can be evaluated
        Evaluation left = getLeftChild().evaluate(attributes);
        Evaluation right = getRightChild().evaluate(attributes);

        // Derive tree evaluation from children
        boolean result = left.isPositive() ^ right.isPositive();
        Instant endOfValidity;
        if (left.isPositive() && right.isPositive()) {
            // Both are positive, XOR is negative
            // -> Earliest time for re-evaluation (min of times) defines end of validity
            endOfValidity = InstantUtility.min(left.getEndOfValidity(), right.getEndOfValidity());
        } else if (left.isPositive()) {
            endOfValidity = left.getEndOfValidity();
        } else if (right.isPositive()) {
            endOfValidity = right.getEndOfValidity();
        } else {
            // Both are negative, XOR is negative
            // -> Earliest time for re-evaluation (min of times) defines end of validity
            endOfValidity = InstantUtility.min(left.getEndOfValidity(), right.getEndOfValidity());
        }
        return new Evaluation(result, endOfValidity);
    }
}
