package com.gstuer.casc.common.attribute.predicate.tree;

import com.gstuer.casc.common.attribute.predicate.PolicyPredicate;

public abstract class PredicateTree extends PolicyPredicate {
    private final PolicyPredicate leftChild;
    private final PolicyPredicate rightChild;

    protected PredicateTree(PolicyPredicate leftChild, PolicyPredicate rightChild) {
        this.leftChild = leftChild;
        this.rightChild = rightChild;
    }

    protected PolicyPredicate getLeftChild() {
        return leftChild;
    }

    protected PolicyPredicate getRightChild() {
        return rightChild;
    }
}
