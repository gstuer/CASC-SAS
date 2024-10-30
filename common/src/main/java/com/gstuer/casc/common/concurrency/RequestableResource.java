package com.gstuer.casc.common.concurrency;

import com.gstuer.casc.common.concurrency.exception.RequestTimeoutException;
import com.gstuer.casc.common.cryptography.Signer;
import com.gstuer.casc.common.message.AccessControlMessage;

import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public abstract class RequestableResource<T> {
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private final Condition empty = this.lock.writeLock().newCondition();
    private final BlockingQueue<AccessControlMessage<?>> messageEgress;
    private final Signer<?> signer;
    private final int retries;
    private final long timeoutNanos;
    private final InetAddress provider;


    private volatile T resource;
    private volatile LocalDateTime requestTime;

    protected RequestableResource(BlockingQueue<AccessControlMessage<?>> messageEgress, Signer<?> signer, int retries,
                                  long timeoutNanos, InetAddress provider) {
        this.messageEgress = Objects.requireNonNull(messageEgress);
        this.signer = Objects.requireNonNull(signer);
        this.retries = retries;
        this.timeoutNanos = timeoutNanos;
        this.provider = Objects.requireNonNull(provider);
    }

    public T get() throws RequestTimeoutException {
        Lock readLock = this.lock.readLock();
        Lock writeLock = this.lock.writeLock();
        readLock.lock();
        try {
            if (resource == null) {
                readLock.unlock();
                writeLock.lock();
                try {
                    int count = 0;
                    while (resource == null) {
                        try {
                            if (count > retries) {
                                break;
                            }
                            if (isUnavailable() && !isRequestPending()) {
                                this.sendRequestMessage();
                            }
                            empty.awaitNanos(timeoutNanos);
                            count++;
                        } catch (InterruptedException exception) {
                            continue;
                        }
                    }
                    readLock.lock();
                } finally {
                    this.empty.signalAll();
                    writeLock.unlock();
                }
            }
            if (resource == null) {
                throw new RequestTimeoutException("Unsatisfied request reached maximum number of retries.");
            }
            return resource;
        } finally {
            readLock.unlock();
        }
    }

    public void set(T resource) {
        Lock writeLock = this.lock.writeLock();
        writeLock.lock();
        this.resource = resource;
        this.empty.signalAll();
        writeLock.unlock();
    }

    public boolean isUnavailable() {
        Lock readLock = this.lock.readLock();
        readLock.lock();
        try {
            return this.resource == null;
        } finally {
            readLock.unlock();
        }
    }

    public boolean isRequestPending() {
        Lock readLock = this.lock.readLock();
        readLock.lock();
        try {
            return this.requestTime != null && LocalDateTime.now().isBefore(requestTime.plusNanos(timeoutNanos));
        } finally {
            readLock.unlock();
        }
    }

    public InetAddress getProvider() {
        return provider;
    }

    public Signer<?> getSigner() {
        return signer;
    }

    protected void sendRequestMessage() {
        AccessControlMessage<?> message = constructRequestMessage();
        this.messageEgress.offer(message);
        this.requestTime = LocalDateTime.now();
    }

    protected abstract AccessControlMessage<?> constructRequestMessage();
}
