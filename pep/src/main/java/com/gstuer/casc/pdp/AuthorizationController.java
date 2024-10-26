package com.gstuer.casc.pdp;

import com.gstuer.casc.common.message.AccessControlMessage;
import com.gstuer.casc.common.pattern.AccessDecision;
import com.gstuer.casc.common.pattern.AccessRequestPattern;
import com.gstuer.casc.common.pattern.EthernetPattern;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

import java.net.InetAddress;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

public class AuthorizationController {
    private ConcurrentHashMap<AccessRequestPattern, String> authorizations;

    public void handleRequest(AccessControlMessage<?> message) {
        // TODO Remove static rules
        /* MAC Addresses
         * - Blueberry  (PEP 192.168.0.60) 00:e0:4c:68:02:40
         * - Blackberry (PEP 192.168.0.61) 00:e0:4c:68:02:69
         */
        EthernetPattern blueToBlack = new EthernetPattern(MacAddress.getByName("00:e0:4c:68:02:40"),
                MacAddress.getByName("00:e0:4c:68:02:69"), EtherType.IPV4);
        EthernetPattern blackToBlue = new EthernetPattern(MacAddress.getByName("00:e0:4c:68:02:69"),
                MacAddress.getByName("00:e0:4c:68:02:40"), EtherType.IPV4);

        try {
            AccessDecision blueToBlackDecision = new AccessDecision(blueToBlack, AccessDecision.Decision.GRANTED,
                    InetAddress.getByName("192.168.0.61"), Instant.now().plusSeconds(60));
            AccessDecision blackToBlueDecision = new AccessDecision(blackToBlue, AccessDecision.Decision.GRANTED,
                    InetAddress.getByName("192.168.0.60"), Instant.now().plusSeconds(60));
            // this.incomingDecisions.put(blueToBlack, blueToBlackDecision);
            // this.incomingDecisions.put(blackToBlue, blackToBlueDecision);
            // this.outgoingDecisions.put(blueToBlack, blueToBlackDecision);
            // this.outgoingDecisions.put(blackToBlue, blackToBlueDecision);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }

        // TODO Add handling of access requests, policy exchanges, & key exchange requests
        throw new UnsupportedOperationException("Not implemented yet.");
    }
}
