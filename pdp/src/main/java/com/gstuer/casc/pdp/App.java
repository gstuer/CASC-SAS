package com.gstuer.casc.pdp;

import com.gstuer.casc.common.cryptography.Authenticator;
import com.gstuer.casc.common.cryptography.AuthenticatorFactory;
import com.gstuer.casc.common.egress.AccessControlMessageEgressHandler;
import com.gstuer.casc.common.ingress.AccessControlMessageIngressHandler;
import com.gstuer.casc.common.message.AccessControlMessage;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
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

        // Parse command line arguments without required options to avoid help dialog not being printed in case of missing arguments
        CommandLine commandLine;
        try {
            commandLine = parseCommandLine(args, false);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Print help dialog if requested by user
        if (commandLine.hasOption("h")) {
            displayHelp();
            return;
        }

        // Parse command line arguments with required options
        try {
            commandLine = parseCommandLine(args, true);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Parse authentication authority (KGC) address from command line arguments
        InetAddress authenticationAuthority;
        String authenticationAuthorityHostname = commandLine.getOptionValue("authentication");
        try {
            authenticationAuthority = InetAddress.getByName(authenticationAuthorityHostname);
        } catch (UnknownHostException exception) {
            System.err.println("Resolving authentication authority hostname failed: " + exception.getMessage());
            return;
        }

        // Parse authenticator from command line arguments
        Optional<Authenticator<?, ?>> optionalAuthenticator = AuthenticatorFactory.createByIdentifier(commandLine.getOptionValue("crypto"));
        if (optionalAuthenticator.isEmpty()) {
            System.err.println("Parsing cryptographic algorithm failed: Unknown algorithm.");
            return;
        }
        Authenticator<?, ?> authenticator = optionalAuthenticator.get();

        // Construct controller
        BlockingQueue<AccessControlMessage<?>> egressQueue = new LinkedBlockingQueue<>();
        AuthorizationController controller = new AuthorizationController(egressQueue, authenticationAuthority, authenticator);

        // Construct ingress and egress handlers
        AccessControlMessageEgressHandler egressHandler = new AccessControlMessageEgressHandler(UDP_PORT_OUTGOING, UDP_PORT_INCOMING, egressQueue);
        AccessControlMessageIngressHandler ingressHandler = new AccessControlMessageIngressHandler(UDP_PORT_INCOMING, controller::handleRequest);

        // Start handler threads
        ExecutorService threadPool = Executors.newFixedThreadPool(2);
        threadPool.submit(egressHandler::open);
        threadPool.submit(ingressHandler::open);
    }

    private static CommandLine parseCommandLine(String[] args, boolean parseWithRequiredOptions) throws ParseException {
        CommandLineParser parser = new DefaultParser(false);
        return parser.parse(getCommandLineOptions(parseWithRequiredOptions), args, false);
    }

    private static void displayHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("app", getCommandLineOptions(true), true);
    }

    private static Options getCommandLineOptions(boolean enableRequiredOptions) {
        Options options = new Options();
        options.addOption(Option.builder()
                .longOpt("authentication")
                .desc("set the hostname or address of the authentication authority")
                .numberOfArgs(1)
                .argName("hostname")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder()
                .longOpt("crypto")
                .desc("set the cryptographic algorithm used for authentication")
                .numberOfArgs(1)
                .argName("algorithm")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder("h")
                .longOpt("help")
                .desc("displays usage information of the program and exit")
                .build());
        return options;
    }
}
