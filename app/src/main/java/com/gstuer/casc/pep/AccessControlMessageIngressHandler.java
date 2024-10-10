package com.gstuer.casc.pep;

import com.gstuer.casc.pep.access.AccessControlMessage;
import com.gstuer.casc.pep.serialization.JsonProcessor;
import com.gstuer.casc.pep.serialization.SerializationException;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.function.Consumer;

public class AccessControlMessageIngressHandler extends IngressHandler<AccessControlMessage<?>> {
    private final int port;
    private DatagramSocket socket;

    public AccessControlMessageIngressHandler(int port, Consumer<AccessControlMessage<?>> messageConsumer) {
        super(messageConsumer);
        this.port = port;
    }

    @Override
    public void open() {
        DatagramSocket socket;
        try {
            socket = new DatagramSocket(new InetSocketAddress("0.0.0.0", port));
            System.out.printf("[Ingress ACM] Buffer size: %d Bytes.\n", socket.getReceiveBufferSize());
            while (!socket.isClosed()) {
                byte[] buffer = new byte[socket.getReceiveBufferSize()];
                DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
                socket.receive(datagram);

                // Remove "empty" bytes from buffer to avoid deserialization issues
                datagram.setData(new DataInputStream(new ByteArrayInputStream(datagram.getData(), datagram.getOffset(), datagram.getLength())).readAllBytes());
                new Thread(() -> this.handle(datagram)).start();
            }
        } catch (IOException exception) {
            System.err.println("[Ingress ACM] Binding socket failed: " + exception.getMessage());
            throw new IllegalStateException(exception);
        } finally {
            System.err.println("[Ingress ACM] Socket closed.");
        }
    }

    @Override
    public void close() {
        this.socket.close();
    }

    protected void handle(DatagramPacket datagram) {
        // Deserialize access control message transmitted
        JsonProcessor jsonProcessor = new JsonProcessor();
        AccessControlMessage<?> message;
        try {
            message = jsonProcessor.deserialize(datagram.getData(), AccessControlMessage.class);
        } catch (SerializationException exception) {
            System.err.println("[Ingress ACM] Deserialization failed: " + exception.getMessage());
            return;
        }

        // Get sender of datagram and set sender of access control message
        InetAddress sender = datagram.getAddress();
        message = message.fromSource(sender);
        System.out.printf("[Ingress ACM] Packet received: %s\n", message);
        super.handle(message);
    }
}
