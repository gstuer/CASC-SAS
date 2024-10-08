package com.gstuer.casc.pep;

import java.util.Objects;
import java.util.concurrent.BlockingQueue;

public abstract class EgressHandler<T> {
    private final BlockingQueue<T> egressQueue;

    protected EgressHandler(BlockingQueue<T> egressQueue) {
        this.egressQueue = Objects.requireNonNull(egressQueue);
    }

    public abstract void open();

    public abstract void handle(T item);

    public abstract void close();

    protected T takeNextQueueItem() throws InterruptedException {
        return this.egressQueue.take();
    }
}
