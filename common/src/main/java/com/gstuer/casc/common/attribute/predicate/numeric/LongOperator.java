package com.gstuer.casc.common.attribute.predicate.numeric;

public enum LongOperator implements NumericOperator<Long> {
    LESS_THAN {
        @Override
        public boolean test(Long referenceValue, Long testValue) {
            if (referenceValue == null) {
                throw new IllegalArgumentException(MISSING_REFERENCE);
            }
            return testValue < referenceValue;
        }
    },
    GREATER_THAN {
        @Override
        public boolean test(Long referenceValue, Long testValue) {
            if (referenceValue == null) {
                throw new IllegalArgumentException(MISSING_REFERENCE);
            }
            return testValue > referenceValue;
        }
    },
    EQUAL {
        @Override
        public boolean test(Long referenceValue, Long testValue) {
            if (referenceValue == null) {
                throw new IllegalArgumentException(MISSING_REFERENCE);
            }
            return testValue.equals(referenceValue);
        }
    };

    public static final String MISSING_REFERENCE = "Performed numeric operation may not be called without reference value.";
}
