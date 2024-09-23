package org.example;

import com.gstuer.casc.pep.forwarding.ForwardingBridge;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.util.List;

public class App {
    public static void main(String[] args) {
        System.out.println("IP/PEP - Intrusion Prevention & Policy Enforcement Point");

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

        // Print list of network interfaces if requested by user
        if (commandLine.hasOption("l")) {
            try {
                displayInterfaceList();
            } catch (PcapNativeException exception) {
                System.err.println("Listing network interfaces failed: " + exception.getMessage());
                return;
            }
        }

        // Parse command line arguments with required options
        try {
            commandLine = parseCommandLine(args, true);
        } catch (ParseException exception) {
            System.err.println(exception.getMessage());
            return;
        }

        // Parse interface identifiers from command line arguments and create pcap interfaces
        PcapNetworkInterface secureNetworkInterface;
        PcapNetworkInterface insecureNetworkInterface;
        String secureInterfaceIdentifier = commandLine.getOptionValue("s");
        String insecureInterfaceIdentifier = commandLine.getOptionValue("i");
        try {
            secureNetworkInterface = Pcaps.getDevByName(secureInterfaceIdentifier);
            insecureNetworkInterface = Pcaps.getDevByName(insecureInterfaceIdentifier);
        } catch (PcapNativeException exception) {
            System.err.println("Setting up interfaces failed: " + exception.getMessage());
            return;
        }

        ForwardingBridge inBridge = new ForwardingBridge(insecureNetworkInterface, secureNetworkInterface);
        ForwardingBridge outBridge = new ForwardingBridge(secureNetworkInterface, insecureNetworkInterface);

        System.out.println("Start Bridge: " + insecureNetworkInterface.getName() + "->" + secureNetworkInterface.getName());
        inBridge.startForwarding();
        System.out.println("Start Bridge: " + secureNetworkInterface.getName() + "->" + insecureNetworkInterface.getName());
        outBridge.startForwarding();
    }

    private static void displayHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("app", getCommandLineOptions(true), true);
    }

    private static void displayInterfaceList() throws PcapNativeException {
        System.out.println("Available Network Interfaces:");
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        for (PcapNetworkInterface device : devices) {
            if (device.isUp() && !device.isLoopBack()) {
                LinkLayerAddress firstLinkLayerAddress = device.getLinkLayerAddresses().stream().findFirst().orElse(null);
                System.out.printf("    %s %s\n", device.getName(), firstLinkLayerAddress);
            }
        }
    }

    private static CommandLine parseCommandLine(String[] args, boolean parseWithRequiredOptions) throws ParseException {
        CommandLineParser parser = new DefaultParser(false);
        return parser.parse(getCommandLineOptions(parseWithRequiredOptions), args, false);
    }

    private static Options getCommandLineOptions(boolean enableRequiredOptions) {
        Options options = new Options();
        options.addOption(Option.builder("s")
                .longOpt("secure")
                .desc("set the secure interface of the program")
                .numberOfArgs(1)
                .argName("interface")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder("i")
                .longOpt("insecure")
                .desc("set the insecure interface of the program")
                .numberOfArgs(1)
                .argName("interface")
                .required(enableRequiredOptions)
                .build());
        options.addOption(Option.builder("l")
                .longOpt("list")
                .desc("displays network interfaces usable as secure or insecure interface of the program")
                .build());
        options.addOption(Option.builder("h")
                .longOpt("help")
                .desc("displays usage information of the program and exit")
                .build());
        return options;
    }
}
