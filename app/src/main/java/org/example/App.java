package org.example;

import com.gstuer.casc.pep.forwarding.ForwardingBridge;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.LinkLayerAddress;

import java.util.List;

public class App {
    public static void main(String[] args) throws PcapNativeException {
        System.out.println("IP/PEP - Intrusion Prevention & Policy Enforcement Point");
        System.out.println("Available Network Interfaces:");
        List<PcapNetworkInterface> devices = Pcaps.findAllDevs();
        for (PcapNetworkInterface device : devices) {
            LinkLayerAddress firstLinkLayerAddress = device.getLinkLayerAddresses().stream().findFirst().orElse(null);
            System.out.printf("    %s %s\n", device.getName(), firstLinkLayerAddress);
        }

        PcapNetworkInterface externalNetworkInterface = Pcaps.getDevByName("enp0s31f6");
        PcapNetworkInterface internalNetworkInterface = Pcaps.getDevByName("enp0s20f0u1c2");

        ForwardingBridge inBridge = new ForwardingBridge(externalNetworkInterface, internalNetworkInterface);
        ForwardingBridge outBridge = new ForwardingBridge(internalNetworkInterface, externalNetworkInterface);

        System.out.println("Start Bridge: " + externalNetworkInterface.getName() + "->" + internalNetworkInterface.getName());
        inBridge.startForwarding();
        System.out.println("Start Bridge: " + internalNetworkInterface.getName() + "->" + externalNetworkInterface.getName());
        outBridge.startForwarding();
    }
}
