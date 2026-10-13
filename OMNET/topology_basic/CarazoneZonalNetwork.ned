//
// CARAZONE — Federated IDS for Automotive Ethernet TSN Zonal Architectures
// FYP26-113-VROOM
//
// Zonal E/E topology:
//
//                            [gm]  (TsnClock, gPTP grandmaster)
//                              |  eth0
//                              |
//            [cvc] ---------[backbone]--------- zone uplinks
//         (central vehicle      |  |  |  |
//          compute, FL server)  |  |  |  |
//                        zone[0] zone[1] zone[2] zone[3]
//                          FL      FR      RL      RR
//                          |        |       |       |
//                       2 ECUs   2 ECUs  2 ECUs  2 ECUs
//
// backbone eth map: eth0=gm, eth1=cvc, eth2=zone[0], eth3=zone[1],
//                   eth4=zone[2], eth5=zone[3]
// zone[i] eth map:  eth0=backbone (gPTP slave port), eth1/eth2 = ECUs
//
// The topology is a tree so that the L2 forwarding is loop-free without STP.
// The redundant backbone ring needed for FRER (802.1CB) is written below but
// commented out — see README section "Enabling the FRER ring".
//

package carazone.simulations;

import inet.common.scenario.ScenarioManager;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.tsn.TsnClock;
import inet.node.tsn.TsnDevice;
import inet.node.tsn.TsnSwitch;

//
// Backbone link between the CVC domain and the zone controllers.
// Automotive Ethernet backbone; 50ns delay ~ 10m of cable.
//
channel BackboneLink extends ned.DatarateChannel
{
    datarate = 100Mbps;
    delay = 50ns;
}

//
// Zone-internal access link from a zone controller to an ECU.
//
channel AccessLink extends ned.DatarateChannel
{
    datarate = 100Mbps;
    delay = 20ns;
}

network CarazoneZonalNetwork
{
    parameters:
        int numZones = default(4);
        int ecusPerZone = default(2);
        @display("bgb=1000,700");

    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,80");
        }
        scenarioManager: ScenarioManager {
            @display("p=100,180");
        }

        // gPTP grandmaster clock
        gm: TsnClock {
            @display("p=500,80");
        }

        // Central Vehicle Compute — federated aggregation server
        cvc: TsnDevice {
            @display("p=750,220");
        }

        // Backbone switch (co-located with the CVC)
        backbone: TsnSwitch {
            @display("p=500,220");
        }

        // Zone controllers — these are the federated clients
        zone[numZones]: TsnSwitch {
            @display("p=200,400,row,200");
        }

        // Zone-local ECUs (sensors / actuators)
        ecu[numZones * ecusPerZone]: TsnDevice {
            @display("p=150,580,row,120");
        }

    connections:
        // --- backbone fan-out, order fixes the eth[] indices ---
        gm.ethg++ <--> BackboneLink <--> backbone.ethg++;      // backbone eth0
        cvc.ethg++ <--> BackboneLink <--> backbone.ethg++;     // backbone eth1

        for i = 0..numZones - 1 {
            // backbone eth(2+i)  <-->  zone[i] eth0
            backbone.ethg++ <--> BackboneLink <--> zone[i].ethg++;
        }

        // --- zone-local ECUs: zone[i] eth1 .. eth(ecusPerZone) ---
        for i = 0..numZones - 1, for j = 0..ecusPerZone - 1 {
            zone[i].ethg++ <--> AccessLink <--> ecu[i * ecusPerZone + j].ethg++;
        }

        // --- FRER ring (v2). Uncomment together with the configurator line
        //     in omnetpp.ini, otherwise this creates an L2 forwarding loop. ---
        // zone[0].ethg++ <--> BackboneLink <--> zone[1].ethg++;
        // zone[1].ethg++ <--> BackboneLink <--> zone[2].ethg++;
        // zone[2].ethg++ <--> BackboneLink <--> zone[3].ethg++;
}
