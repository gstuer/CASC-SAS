package com.gstuer.casc.common.attribute.predicate.tree;

import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;

/**
 * Represents a {@link PredicateTree tree of predicates} that uses the logical operators to evaluate its underlying
 * {@link PolicyPredicate policy predicates}.
 */
public abstract class PredicateTree extends PolicyPredicate {
    private final PolicyPredicate leftChild;
    private final PolicyPredicate rightChild;

    /**
     * Constructs a new {@link PredicateTree}.
     *
     * @param leftChild  first child node of the tree
     * @param rightChild second child node of the tree
     */
    protected PredicateTree(PolicyPredicate leftChild, PolicyPredicate rightChild) {
        this.leftChild = leftChild;
        this.rightChild = rightChild;
    }

    /**
     * Gets the first child node of the tree.
     *
     * @return first child node of the tree.
     */
    protected PolicyPredicate getLeftChild() {
        return leftChild;
    }

    /**
     * Gets the second child node of the tree.
     *
     * @return second child node of the tree.
     */
    protected PolicyPredicate getRightChild() {
        return rightChild;
    }
}
