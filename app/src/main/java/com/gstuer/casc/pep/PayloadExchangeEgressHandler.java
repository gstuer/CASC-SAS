package com.gstuer.casc.pep;

import com.gstuer.casc.pep.access.PayloadExchangeMessage;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.concurrent.BlockingQueue;

public class PayloadExchangeEgressHandler extends EgressHandler<PayloadExchangeMessage> {
    private static final int PORT = 10000;
    private DatagramSocket socket;

    public PayloadExchangeEgressHandler(BlockingQueue<PayloadExchangeMessage> egressQueue) {
        super(egressQueue);
    }

    @Override
    public void open() {
        if (this.isOpen()) {
            throw new IllegalStateException("Handler already open.");
        }

        // Try to open a new datagram socket (UDP communication)
        try {
            this.socket = new DatagramSocket(PORT);
        } catch (SocketException exception) {
            throw new IllegalStateException("UDP egress handler cannot be opened for port " + PORT, exception);
        }

        while (this.isOpen()) {
            PayloadExchangeMessage message;
            try {
                message = takeNextQueueItem();
            } catch (InterruptedException exception) {
                // Handler interrupted during waiting for new packet
                break;
            }
            handle(message);
        }
        System.out.println("[Egress Payload Exchange] Handler closed.");
    }

    @Override
    public void handle(PayloadExchangeMessage message) {
        if (this.socket == null) {
            throw new IllegalStateException("Handler not opened yet.");
        } else if (this.socket.isClosed()) {
            throw new IllegalStateException("Handler already closed.");
        }

        try {
            byte[] serialMessage = new JsonProcessor().serialize(message);
            SocketAddress receiverSocketAddress = new InetSocketAddress(message.getDestination(), PORT);
            DatagramPacket packet = new DatagramPacket(serialMessage, serialMessage.length, receiverSocketAddress);
            this.socket.send(packet);
        } catch (SerializationException exception) {
            System.out.println("[Egress Payload Exchange] Serialization failed:" + exception.getMessage());
            return;
        } catch (IOException exception) {
            System.out.println("[Egress Payload Exchange] Sending failed:" + exception.getMessage());
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
