package com.gstuer.casc.pep;

import com.gstuer.casc.pep.access.AccessControlMessage;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.BlockingQueue;

public class AccessControlMessageEgressHandler extends EgressHandler<AccessControlMessage<?>> {
    private final int port;
    private DatagramSocket socket;

    public AccessControlMessageEgressHandler(int port, BlockingQueue<AccessControlMessage<?>> egressQueue) {
        super(egressQueue);
        this.port = port;
    }

    @Override
    public void open() {
        if (this.isOpen()) {
            throw new IllegalStateException("Handler already open.");
        }

        // Try to open a new datagram socket (UDP communication)
        try {
            this.socket = new DatagramSocket(null);
            this.socket.setReuseAddress(true);
            this.socket.bind(new InetSocketAddress(port));
        } catch (SocketException exception) {
            throw new IllegalStateException("UDP egress handler cannot be opened for port " + this.port, exception);
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
            SocketAddress receiverSocketAddress = new InetSocketAddress(message.getDestination(), this.port);
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
