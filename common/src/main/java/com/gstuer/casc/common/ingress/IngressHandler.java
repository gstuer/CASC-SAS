package com.gstuer.casc.common.ingress;

import java.util.Objects;
import java.util.function.Consumer;

public abstract class IngressHandler<T> {
    private final Consumer<T> consumer;

    protected IngressHandler(Consumer<T> consumer) {
        this.consumer = Objects.requireNonNull(consumer);
    }

    public abstract void open();

    public abstract void close();

    protected void handle(T item) {
        this.consumer.accept(item);
    }
}
