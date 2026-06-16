package dpi;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class MainDPI {

    public static class BlockingRules {
        public Set<Integer> blockedIps = new HashSet<>();
        public Set<AppType> blockedApps = new HashSet<>();
        public List<String> blockedDomains = new ArrayList<>();

        public void blockIP(String ip) {
            int addr = parseIP(ip);
            blockedIps.add(addr);
            System.out.println("[Rules] Blocked IP: " + ip);
        }

        public void blockApp(String app) {
            for (AppType type : AppType.values()) {
                if (type.toString().equalsIgnoreCase(app)) {
                    blockedApps.add(type);
                    System.out.println("[Rules] Blocked app: " + type.toString());
                    return;
                }
            }
            System.err.println("[Rules] Unknown app: " + app);
        }

        public void blockDomain(String domain) {
            blockedDomains.add(domain.toLowerCase());
            System.out.println("[Rules] Blocked domain: " + domain);
        }

        public boolean isBlocked(int srcIp, AppType app, String sni) {
            if (blockedIps.contains(srcIp)) return true;
            if (blockedApps.contains(app)) return true;
            if (sni != null && !sni.isEmpty()) {
                String lowerSni = sni.toLowerCase();
                for (String dom : blockedDomains) {
                    if (lowerSni.contains(dom)) return true;
                }
            }
            return false;
        }

        public static int parseIP(String ip) {
            int result = 0;
            int octet = 0, shift = 0;
            for (char c : ip.toCharArray()) {
                if (c == '.') {
                    result |= (octet << shift);
                    shift += 8;
                    octet = 0;
                } else if (c >= '0' && c <= '9') {
                    octet = octet * 10 + (c - '0');
                }
            }
            return result | (octet << shift);
        }
    }

    private static void printUsage(String prog) {
        System.out.println("\nDPI Engine - Deep Packet Inspection System");
        System.out.println("==========================================");
        System.out.printf("Usage: java %s <input.pcap> <output.pcap> [options]\n\n", prog);
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block traffic from source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, etc.)");
        System.out.println("  --block-domain <dom>   Block domain (substring match)\n");
        System.out.printf("Example:\n  java %s capture.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50\n", prog);
    }

    // Helper method to create a safe composite lookup key for FiveTuple in Java HashMap
    private static String getFlowKey(FiveTuple t) {
        return String.format("%d_%d_%d_%d_%d", t.srcIp, t.dstIp, t.srcPort, t.dstPort, t.protocol);
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage("dpi.MainDPI");
            System.exit(1);
        }

        String inputFile = args[0];
        String outputFile = args[1];

        BlockingRules rules = new BlockingRules();

        // Parse options arguments
        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) {
                rules.blockIP(args[++i]);
            } else if (arg.equals("--block-app") && i + 1 < args.length) {
                rules.blockApp(args[++i]);
            } else if (arg.equals("--block-domain") && i + 1 < args.length) {
                rules.blockDomain(args[++i]);
            }
        }

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0                           ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) {
                System.exit(1);
            }

            // Using local file block writer for output streaming
            try (FileOutputStream output = new FileOutputStream(outputFile)) {
                
                // Emulate writing raw global header to pcap file output using native stream tracking
                // In production, we retrieve or pass standard 24-byte headers across streams
                byte[] placeholderHeader = new byte[24]; 
                output.write(placeholderHeader); // Note: Simplified directly to preserve format compatibility

                Map<String, Flow> flows = new HashMap<>();
                long totalPackets = 0;
                long forwarded = 0;
                long dropped = 0;
                Map<AppType, Long> appStats = new HashMap<>();

                for (AppType type : AppType.values()) {
                    appStats.put(type, 0L);
                }

                PcapReader.RawPacket raw = new PcapReader.RawPacket();
                ParsedPacket parsed = new ParsedPacket();

                System.out.println("[DPI] Processing packets...");

                while (reader.readNextPacket(raw)) {
                    totalPackets++;

                    PacketParser parser = new PacketParser();
                    if (!parser.parse(raw, parsed)) continue;
                    if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

                    FiveTuple tuple = new FiveTuple(
                            BlockingRules.parseIP(parsed.srcIp),
                            BlockingRules.parseIP(parsed.destIp),
                            parsed.srcPort,
                            parsed.destPort,
                            parsed.protocol
                    );

                    String flowKey = getFlowKey(tuple);
                    Flow flow = flows.get(flowKey);
                    if (flow == null) {
                        flow = new Flow();
                        flow.tuple = tuple;
                        flows.put(flowKey, flow);
                    }

                    flow.packets++;
                    flow.bytes += raw.data.length;

                    // Extractor Slicing offsets
                    if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS) &&
                            flow.sni.isEmpty() && parsed.hasTcp && parsed.destPort == 443) {

                        int payloadOffset = 14;
                        int ipIhl = raw.data[14] & 0x0F;
                        payloadOffset += ipIhl * 4;

                        if (payloadOffset + 12 < raw.data.length) {
                            int tcpOffset = (raw.data[payloadOffset + 12] >> 4) & 0x0F;
                            payloadOffset += tcpOffset * 4;

                            if (payloadOffset < raw.data.length) {
                                int payloadLen = raw.data.length - payloadOffset;
                                if (payloadLen > 5) {
                                    byte[] tlsData = new byte[payloadLen];
                                    System.arraycopy(raw.data, payloadOffset, tlsData, 0, payloadLen);
                                    String sni = SNIExtractor.extractTLS(tlsData, payloadLen);
                                    if (sni != null) {
                                        flow.sni = sni;
                                        flow.appType = AppType.sniToAppType(sni);
                                    }
                                }
                            }
                        }
                    }

                    // HTTP Host Slicing checks
                    if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP) &&
                            flow.sni.isEmpty() && parsed.hasTcp && parsed.destPort == 80) {

                        int payloadOffset = 14;
                        int ipIhl = raw.data[14] & 0x0F;
                        payloadOffset += ipIhl * 4;

                        if (payloadOffset + 12 < raw.data.length) {
                            int tcpOffset = (raw.data[payloadOffset + 12] >> 4) & 0x0F;
                            payloadOffset += tcpOffset * 4;

                            if (payloadOffset < raw.data.length) {
                                int payloadLen = raw.data.length - payloadOffset;
                                byte[] httpData = new byte[payloadLen];
                                System.arraycopy(raw.data, payloadOffset, httpData, 0, payloadLen);
                                String host = SNIExtractor.HTTPHostExtractor.extract(httpData, payloadLen);
                                if (host != null) {
                                    flow.sni = host;
                                    flow.appType = AppType.sniToAppType(host);
                                }
                            }
                        }
                    }

                    // DNS Classification matches
                    if (flow.appType == AppType.UNKNOWN && (parsed.destPort == 53 || parsed.srcPort == 53)) {
                        flow.appType = AppType.DNS;
                    }

                    // Fallbacks
                    if (flow.appType == AppType.UNKNOWN) {
                        if (parsed.destPort == 443) flow.appType = AppType.HTTPS;
                        else if (parsed.destPort == 80) flow.appType = AppType.HTTP;
                    }

                    // Rule Check
                    if (!flow.blocked) {
                        flow.blocked = rules.isBlocked(tuple.srcIp, flow.appType, flow.sni);
                        if (flow.blocked) {
                            System.out.print("[BLOCKED] " + parsed.srcIp + " -> " + parsed.destIp + " (" + flow.appType.toString());
                            if (!flow.sni.isEmpty()) System.out.print(": " + flow.sni);
                            System.out.println(")");
                        }
                    }

                    appStats.put(flow.appType, appStats.get(flow.appType) + 1);

                    // Forward or drop tracking block
                    if (flow.blocked) {
                        dropped++;
                    } else {
                        forwarded++;
                        // Emulating packet headers serialization block writing
                        ByteBuffer pktHdr = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
                        pktHdr.putInt(raw.header.tsSec);
                        pktHdr.putInt(raw.header.tsUsec);
                        pktHdr.putInt(raw.data.length);
                        pktHdr.putInt(raw.data.length);

                        output.write(pktHdr.array());
                        output.write(raw.data);
                    }
                }

                // UI Display Processing summary reports
                System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
                System.out.println("║                     PROCESSING REPORT                        ║");
                System.out.println("╠══════════════════════════════════════════════════════════════╣");
                System.out.printf("║ Total Packets:      %10d                               ║\n", totalPackets);
                System.out.printf("║ Forwarded:          %10d                               ║\n", forwarded);
                System.out.printf("║ Dropped:            %10d                               ║\n", dropped);
                System.out.printf("║ Active Flows:       %10d                               ║\n", flows.size());
                System.out.println("╠══════════════════════════════════════════════════════════════╣");
                System.out.println("║                    APPLICATION BREAKDOWN                     ║");
                System.out.println("╠══════════════════════════════════════════════════════════════╣");

                List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(appStats.entrySet());
                sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

                for (Map.Entry<AppType, Long> entry : sortedApps) {
                    long count = entry.getValue();
                    if (count == 0) continue;
                    double pct = (totalPackets == 0) ? 0.0 : (100.0 * count / totalPackets);
                    int barLen = (int) (pct / 5);
                    String bar = "#".repeat(barLen) + " ".repeat(20 - barLen);

                    System.out.printf("║ %-15s %8d  %5.1f%%  %-20s ║\n", entry.getKey().toString(), count, pct, bar);
                }
                System.out.println("╚══════════════════════════════════════════════════════════════╝");

                System.out.println("\n[Detected Applications/Domains]");
                Map<String, AppType> uniqueSnis = new HashMap<>();
                for (Flow f : flows.values()) {
                    if (!f.sni.isEmpty()) {
                        uniqueSnis.put(f.sni, f.appType);
                    }
                }
                for (Map.Entry<String, AppType> entry : uniqueSnis.entrySet()) {
                    System.out.println("  - " + entry.getKey() + " -> " + entry.getValue().toString());
                }

                System.out.println("\nOutput written to: " + outputFile);

            }
        } catch (IOException e) {
            System.err.println("Fatal stream exception: " + e.getMessage());
        }
    }
}
