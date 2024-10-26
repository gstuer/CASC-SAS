package com.gstuer.casc.pep.predicate;

import org.pcap4j.packet.Packet;

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

/**
 * Represents a {@link Predicate predicate} that is evaluated on {@link Packet packet} objects.
 */
public abstract class PacketPredicate implements Predicate<Packet> {
    public static PacketPredicate getStaticPredicate(boolean isMatching) {
        return new PacketPredicate() {
            @Override
            public boolean test(Packet packet) {
                return isMatching;
            }
        };
    }

    /**
     * Constructs a {@link PacketPredicate} from a {@link Predicate Predicate&lt;Packet&gt;} instance.
     *
     * @param predicate the original predicate
     * @return a new {@link PacketPredicate}
     */
    public static PacketPredicate from(Predicate<Packet> predicate) {
        return new PacketPredicate() {
            @Override
            public boolean test(Packet packet) {
                return predicate.test(packet);
            }
        };
    }

    /**
     * Applies a {@link Consumer consumer} on a {@link Packet packet} if the packet matches this predicate.
     *
     * @param packet   the tested and potentially consumed packet
     * @param consumer the packet-consuming void-returning operation
     */
    public void doIfMatches(Packet packet, Consumer<Packet> consumer) {
        if (this.test(packet)) {
            consumer.accept(packet);
        }
    }

    /**
     * Applies a {@link Consumer consumer} on a {@link Packet packet} if the packet matches this predicate,
     * applies an alternative consumer otherwise.
     *
     * @param packet           the tested and consumed packet
     * @param matchConsumer    the packet-consuming void-returning operation applied in case of a match
     * @param mismatchConsumer the packet-consuming void-returning operation applied in case of a mismatch
     */
    public void doIfMatchesOrElse(Packet packet, Consumer<Packet> matchConsumer, Consumer<Packet> mismatchConsumer) {
        if (this.test(packet)) {
            matchConsumer.accept(packet);
        } else {
            mismatchConsumer.accept(packet);
        }
    }

    /**
     * Applies a {@link Function function} on a {@link Packet packet}, if the packet matches this predicate.
     *
     * @param packet   the tested and potentially consumed packet
     * @param function the packet-consuming function
     * @param <R>      the return type of the packet-consuming function
     * @return the return value of the function if the packet matches, an empty {@link Optional optional} otherwise
     */
    public <R> Optional<R> doIfMatches(Packet packet, Function<Packet, R> function) {
        if (this.test(packet)) {
            return Optional.ofNullable(function.apply(packet));
        } else {
            return Optional.empty();
        }
    }

    @Override
    public PacketPredicate and(Predicate<? super Packet> other) {
        return PacketPredicate.from(Predicate.super.and(other));
    }

    @Override
    public PacketPredicate negate() {
        return PacketPredicate.from(Predicate.super.negate());
    }

    @Override
    public PacketPredicate or(Predicate<? super Packet> other) {
        return PacketPredicate.from(Predicate.super.or(other));
    }
}