package com.gstuer.casc.common.attribute;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

public class AttributePublisher {
    private final ConcurrentMap<AttributeIdentifier, PolicyAttribute<?>> attributes;
    private final ConcurrentMap<AttributeIdentifier, AttributeUpdater> updaters;

    public AttributePublisher() {
        this.attributes = new ConcurrentHashMap<>();
        this.updaters = new ConcurrentHashMap<>();
    }

    public <T> void publish(PolicyAttribute<T> attribute) {
        if (!attribute.hasValueSupplier()) {
            throw new IllegalArgumentException("Cannot publish attribute without value supplier.");
        }
        this.attributes.put(attribute.getIdentifier(), attribute);

        // Create and start updater thread for published attribute
        AttributeUpdater updater = new AttributeUpdater(attribute);
        this.updaters.put(attribute.getIdentifier(), updater);
        new Thread(updater).start();
    }

    public void unpublish(PolicyAttribute<?> attribute) {
        this.unpublish(attribute.getIdentifier());
    }

    public void unpublish(AttributeIdentifier identifier) {
        this.attributes.remove(identifier);
        AttributeUpdater updater = this.updaters.get(identifier);
        if (Objects.nonNull(updater)) {
            updater.stop();
            this.updaters.remove(identifier);
        }
    }

    public PolicyAttribute<?> get(AttributeIdentifier identifier) {
        return this.attributes.get(identifier);
    }

    private static final class AttributeUpdater implements Runnable {
        private final static Duration REFRESH_THRESHOLD = Duration.ofMillis(10);
        private final static Duration SLEEP_OFFSET = Duration.ofMillis(5);
        private final PolicyAttribute<?> attribute;
        private boolean isRunning = true;

        private AttributeUpdater(PolicyAttribute<?> attribute) {
            this.attribute = Objects.requireNonNull(attribute);
        }

        @Override
        public void run() {
            while (isRunning) {
                Instant now = Instant.now();
                long millisecondsLeft = now.until(attribute.getValidUntil(), TimeUnit.MILLISECONDS.toChronoUnit());
                if (millisecondsLeft < REFRESH_THRESHOLD.toMillis()) {
                    // If less time than threshold is left, update value of attribute
                    attribute.update();
                } else {
                    // If more time than threshold is left, sleep for left time minus offset
                    try {
                        Thread.sleep(millisecondsLeft - SLEEP_OFFSET.toMillis());
                    } catch (InterruptedException exception) {
                        this.isRunning = false;
                        break;
                    }
                }
            }
        }

        /**
         * Stops this updater safely, i.e., without interrupting it but by stopping the execution after the next sleep
         * period.
         */
        public void stop() {
            this.isRunning = false;
        }
    }
}
