package com.gstuer.casc.common.time;

import java.time.Instant;

public final class InstantUtility {
    private InstantUtility() {
        throw new IllegalStateException();
    }

    public static Instant max(Instant instant, Instant otherInstant) {
        return instant.isAfter(otherInstant) ? instant : otherInstant;
    }

    public static Instant min(Instant instant, Instant otherInstant) {
        return instant.isAfter(otherInstant) ? otherInstant : instant;
    }
}
