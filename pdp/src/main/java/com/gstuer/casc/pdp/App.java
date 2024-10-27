package com.gstuer.casc.pdp;

import com.gstuer.casc.common.egress.AccessControlMessageEgressHandler;
import com.gstuer.casc.common.ingress.AccessControlMessageIngressHandler;
import com.gstuer.casc.common.message.AccessControlMessage;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

public class App {
    private static final int UDP_PORT_INCOMING = 10000;
    private static final int UDP_PORT_OUTGOING = 10001;

    public static void main(String[] args) {
        System.out.println("PDP - Policy Decision Point");

        // Configure SLF4J logging verbosity
        System.setProperty("slf4j.internal.verbosity", "WARN");
        System.setProperty("org.slf4j.simpleLogger.defaultLogLevel", "WARN");

        // Construct controller
        BlockingQueue<AccessControlMessage<?>> egressQueue = new LinkedBlockingQueue<>();
        AuthorizationController controller = new AuthorizationController(egressQueue);

        // Construct ingress and egress handlers
        AccessControlMessageEgressHandler egressHandler = new AccessControlMessageEgressHandler(UDP_PORT_OUTGOING, UDP_PORT_INCOMING, egressQueue);
        AccessControlMessageIngressHandler ingressHandler = new AccessControlMessageIngressHandler(UDP_PORT_INCOMING, controller::handleRequest);

        // Start handler threads
        ExecutorService threadPool = Executors.newFixedThreadPool(2);
        threadPool.submit(egressHandler::open);
        threadPool.submit(ingressHandler::open);
    }
}
