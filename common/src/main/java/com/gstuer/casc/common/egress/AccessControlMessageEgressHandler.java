package com.gstuer.casc.common.egress;

import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.serialization.JsonProcessor;
import com.gstuer.casc.common.serialization.SerializationException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.BlockingQueue;

public class AccessControlMessageEgressHandler extends EgressHandler<AccessControlMessage<?>> {
    private final int sourcePort;
    private final int destinationPort;
    private DatagramSocket socket;

    public AccessControlMessageEgressHandler(int sourcePort, int destinationPort, BlockingQueue<AccessControlMessage<?>> egressQueue) {
        super(egressQueue);
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
    }

    @Override
    public void open() {
        if (this.isOpen()) {
            throw new IllegalStateException("Handler already open.");
        }

        // Try to open a new datagram socket (UDP communication)
        try {
            socket = new DatagramSocket(new InetSocketAddress("0.0.0.0", this.sourcePort));
        } catch (SocketException exception) {
            throw new IllegalStateException("UDP egress handler cannot be opened for port " + this.sourcePort, exception);
        }

        while (this.isOpen()) {
            AccessControlMessage<?> message;
            try {
                message = takeNextQueueItem();
            } catch (InterruptedException exception) {
                // Handler interrupted during waiting for new packet
                break;
            }
            handle(message);
        }
        System.out.println("[Egress ACM] Handler closed.");
    }

    @Override
    public void handle(AccessControlMessage<?> message) {
        if (this.socket == null) {
            throw new IllegalStateException("Handler not opened yet.");
        } else if (this.socket.isClosed()) {
            throw new IllegalStateException("Handler already closed.");
        }

        try {
            byte[] serialMessage = new JsonProcessor().serialize(message);
            SocketAddress receiverSocketAddress = new InetSocketAddress(message.getDestination(), this.destinationPort);
            DatagramPacket packet = new DatagramPacket(serialMessage, serialMessage.length, receiverSocketAddress);
            this.socket.send(packet);
        } catch (SerializationException exception) {
            System.out.println("[Egress ACM] Serialization failed:" + exception.getMessage());
            return;
        } catch (IOException exception) {
            System.out.println("[Egress ACM] Sending failed:" + exception.getMessage());
            return;
        }
    }

    @Override
    public void close() {
        this.socket.close();
    }

    public boolean isOpen() {
        return this.socket != null && !this.socket.isClosed();
    }
}
