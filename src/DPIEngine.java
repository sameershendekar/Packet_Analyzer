package dpi;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class DPIEngine {

    // =============================================================================
    // Packet Struct
    // =============================================================================
    public static class Packet {
        public int id;
        public int tsSec;
        public int tsUsec;
        public FiveTuple tuple;
        public byte[] data;
        public int tcpFlags;
        public int payloadOffset;
        public int payloadLength;
    }

    // =============================================================================
    // Flow Entry
    // =============================================================================
    public static class FlowEntry {
        public FiveTuple tuple;
        public AppType appType = AppType.UNKNOWN;
        public String sni = "";
        public long packets = 0;
        public long bytes = 0;
        public boolean blocked = false;
        public boolean classified = false;
    }

    // =============================================================================
    // Blocking Rules (Thread-Safe)
    // =============================================================================
    public static class Rules {
        private final Set<Integer> blockedIps = ConcurrentHashMap.newKeySet();
        private final Set<AppType> blockedApps = ConcurrentHashMap.newKeySet();
        private final List<String> blockedDomains = new CopyOnWriteArrayList<>();

        public void blockIP(String ip) {
            blockedIps.add(parseIP(ip));
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

        private static int parseIP(String ip) {
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

    // =============================================================================
    // Statistics (Thread-Safe)
    // =============================================================================
    public static class Stats {
        public final AtomicLong totalPackets = new AtomicLong(0);
        public final AtomicLong totalBytes = new AtomicLong(0);
        public final AtomicLong forwarded = new AtomicLong(0);
        public final AtomicLong dropped = new AtomicLong(0);
        public final AtomicLong tcpPackets = new AtomicLong(0);
        public final AtomicLong udpPackets = new AtomicLong(0);

        public final Map<AppType, Long> appCounts = new ConcurrentHashMap<>();
        public final Map<String, AppType> detectedSnis = new ConcurrentHashMap<>();

        public Stats() {
            for (AppType type : AppType.values()) {
                appCounts.put(type, 0L);
            }
        }

        public void recordApp(AppType app, String sni) {
            appCounts.merge(app, 1L, Long::sum);
            if (sni != null && !sni.isEmpty()) {
                detectedSnis.put(sni, app);
            }
        }
    }

    // =============================================================================
    // Fast Path Processor
    // =============================================================================
    public static class FastPath implements Runnable {
        private final int id;
        private final Rules rules;
        private final Stats stats;
        private final LinkedBlockingQueue<Packet> outputQueue;
        private final LinkedBlockingQueue<Packet> inputQueue = new LinkedBlockingQueue<>(10000);
        private final Map<String, FlowEntry> flows = new HashMap<>();
        private final AtomicBoolean running = new AtomicBoolean(false);
        private final AtomicLong processed = new AtomicLong(0);

        public FastPath(int id, Rules rules, Stats stats, LinkedBlockingQueue<Packet> outputQueue) {
            this.id = id;
            this.rules = rules;
            this.stats = stats;
            this.outputQueue = outputQueue;
        }

        public LinkedBlockingQueue<Packet> queue() { return inputQueue; }
        public long processed() { return processed.get(); }
        public void stop() { running.set(false); }

        @Override
        public void run() {
            running.set(true);
            while (running.get() || !inputQueue.isEmpty()) {
                try {
                    Packet pkt = inputQueue.poll(50, TimeUnit.MILLISECONDS);
                    if (pkt == null) continue;

                    processed.incrementAndGet();
                    String flowKey = String.format("%d_%d_%d_%d_%d", pkt.tuple.srcIp, pkt.tuple.dstIp, pkt.tuple.srcPort, pkt.tuple.dstPort, pkt.tuple.protocol);
                    
                    FlowEntry flow = flows.get(flowKey);
                    if (flow == null) {
                        flow = new FlowEntry();
                        flow.tuple = pkt.tuple;
                        flows.put(flowKey, flow);
                    }
                    flow.packets++;
                    flow.bytes += pkt.data.length;

                    if (!flow.classified) {
                        classifyFlow(pkt, flow);
                    }

                    if (!flow.blocked) {
                        flow.blocked = rules.isBlocked(pkt.tuple.srcIp, flow.appType, flow.sni);
                    }

                    stats.recordApp(flow.appType, flow.sni);

                    if (flow.blocked) {
                        stats.dropped.incrementAndGet();
                    } else {
                        stats.forwarded.incrementAndGet();
                        outputQueue.put(pkt);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        private void classifyFlow(Packet pkt, FlowEntry flow) {
            if (pkt.tuple.dstPort == 443 && pkt.payloadLength > 5) {
                byte[] tlsData = new byte[pkt.payloadLength];
                System.arraycopy(pkt.data, pkt.payloadOffset, tlsData, 0, pkt.payloadLength);
                String sni = SNIExtractor.extractTLS(tlsData, pkt.payloadLength);
                if (sni != null) {
                    flow.sni = sni;
                    flow.appType = AppType.sniToAppType(sni);
                    flow.classified = true;
                    return;
                }
            }

            if (pkt.tuple.dstPort == 80 && pkt.payloadLength > 10) {
                byte[] httpData = new byte[pkt.payloadLength];
                System.arraycopy(pkt.data, pkt.payloadOffset, httpData, 0, pkt.payloadLength);
                String host = SNIExtractor.HTTPHostExtractor.extract(httpData, pkt.payloadLength);
                if (host != null) {
                    flow.sni = host;
                    flow.appType = AppType.sniToAppType(host);
                    flow.classified = true;
                    return;
                }
            }

            if (pkt.tuple.dstPort == 53 || pkt.tuple.srcPort == 53) {
                flow.appType = AppType.DNS;
                flow.classified = true;
                return;
            }

            if (pkt.tuple.dstPort == 443) {
                flow.appType = AppType.HTTPS;
            } else if (pkt.tuple.dstPort == 80) {
                flow.appType = AppType.HTTP;
            }
        }
    }

    // =============================================================================
    // Load Balancer
    // =============================================================================
    public static class LoadBalancer implements Runnable {
        private final int id;
        private final List<FastPath> fps;
        private final int numFps;
        private final LinkedBlockingQueue<Packet> inputQueue = new LinkedBlockingQueue<>(10000);
        private final AtomicBoolean running = new AtomicBoolean(false);
        private final AtomicLong dispatched = new AtomicLong(0);

        public LoadBalancer(int id, List<FastPath> fps) {
            this.id = id;
            this.fps = fps;
            this.numFps = fps.size();
        }

        public LinkedBlockingQueue<Packet> queue() { return inputQueue; }
        public long dispatched() { return dispatched.get(); }
        public void stop() { running.set(false); }

        @Override
        public void run() {
            running.set(true);
            while (running.get() || !inputQueue.isEmpty()) {
                try {
                    Packet pkt = inputQueue.poll(50, TimeUnit.MILLISECONDS);
                    if (pkt == null) continue;

                    // Consistent Session Hashing across elements
                    int hash = Objects.hash(pkt.tuple.srcIp, pkt.tuple.dstIp, pkt.tuple.srcPort, pkt.tuple.dstPort, pkt.tuple.protocol);
                    int fpIdx = Math.abs(hash) % numFps;

                    fps.get(fpIdx).queue().put(pkt);
                    dispatched.incrementAndGet();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }

    // =============================================================================
    // Driver Configurations
    // =============================================================================
    public static class Config {
        public int numLbs = 2;
        public int fpsPerLb = 2;
    }

    private final Config config;
    private final Rules rules = new Rules();
    private final Stats stats = new Stats();
    private final LinkedBlockingQueue<Packet> outputQueue = new LinkedBlockingQueue<>(20000);
    private final List<FastPath> fps = new ArrayList<>();
    private final List<LoadBalancer> lbs = new ArrayList<>();

    public DPIEngine(Config cfg) {
        this.config = cfg;
        int totalFps = cfg.numLbs * cfg.fpsPerLb;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║              DPI ENGINE v2.0 (Multi-threaded)                ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Load Balancers: %2d     FPs per LB: %2d     Total FPs: %2d      ║\n", cfg.numLbs, cfg.fpsPerLb, totalFps);
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

        for (int i = 0; i < totalFps; i++) {
            fps.add(new FastPath(i, rules, stats, outputQueue));
        }

        for (int lb = 0; lb < cfg.numLbs; lb++) {
            List<FastPath> lbFps = new ArrayList<>();
            int start = lb * cfg.fpsPerLb;
            for (int i = 0; i < cfg.fpsPerLb; i++) {
                lbFps.add(fps.get(start + i));
            }
            lbs.add(new LoadBalancer(lb, lbFps));
        }
    }

    public void blockIP(String ip) { rules.blockIP(ip); }
    public void blockApp(String app) { rules.blockApp(app); }
    public void blockDomain(String dom) { rules.blockDomain(dom); }

    public boolean process(String inputFile, String outputFile) {
        try (PcapReader reader = new PcapReader()) {
            if (!reader.open(inputFile)) return false;

            try (FileOutputStream output = new FileOutputStream(outputFile)) {
                // Emulate PCAP Header
                output.write(new byte[24]);

                ExecutorService threadPool = Executors.newCachedThreadPool();
                fps.forEach(threadPool::submit);
                lbs.forEach(threadPool::submit);

                AtomicBoolean outputRunning = new AtomicBoolean(true);
                Future<?> outputFuture = threadPool.submit(() -> {
                    while (outputRunning.get() || !outputQueue.isEmpty()) {
                        try {
                            Packet pkt = outputQueue.poll(50, TimeUnit.MILLISECONDS);
                            if (pkt == null) continue;

                            ByteBuffer phdr = ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
                            phdr.putInt(pkt.tsSec);
                            phdr.putInt(pkt.tsUsec);
                            phdr.putInt(pkt.data.length);
                            phdr.putInt(pkt.data.length);

                            output.write(phdr.array());
                            output.write(pkt.data);
                        } catch (IOException | InterruptedException ignored) {}
                    }
                });

                System.out.println("[Reader] Processing packets...");
                PcapReader.RawPacket raw = new PcapReader.RawPacket();
                ParsedPacket parsed = new ParsedPacket();
                int pktId = 0;

                while (reader.readNextPacket(raw)) {
                    PacketParser parser = new PacketParser();
                    if (!parser.parse(raw, parsed)) continue;
                    if (!parsed.hasIp || (!parsed.hasTcp && !parsed.hasUdp)) continue;

                    Packet pkt = new Packet();
                    pkt.id = pktId++;
                    pkt.tsSec = raw.header.tsSec;
                    pkt.tsUsec = raw.header.tsUsec;
                    pkt.tcpFlags = parsed.tcpFlags;
                    pkt.data = raw.data;

                    pkt.tuple = new FiveTuple(
                            Rules.parseIP(parsed.srcIp),
                            Rules.parseIP(parsed.destIp),
                            parsed.srcPort,
                            parsed.destPort,
                            parsed.protocol
                    );

                    pkt.payloadOffset = 14;
                    if (pkt.data.length > 14) {
                        int ipIhl = pkt.data[14] & 0x0F;
                        pkt.payloadOffset += ipIhl * 4;

                        if (parsed.hasTcp && pkt.payloadOffset + 12 < pkt.data.length) {
                            int tcpOff = (pkt.data[pkt.payloadOffset + 12] >> 4) & 0x0F;
                            pkt.payloadOffset += tcpOff * 4;
                        } else if (parsed.hasUdp) {
                            pkt.payloadOffset += 8;
                        }
                        pkt.payloadLength = Math.max(0, pkt.data.length - pkt.payloadOffset);
                    }

                    stats.totalPackets.incrementAndGet();
                    stats.totalBytes.addAndGet(pkt.data.length);
                    if (parsed.hasTcp) stats.tcpPackets.incrementAndGet();
                    else stats.udpPackets.incrementAndGet();

                    int lbIdx = Math.abs(Objects.hash(pkt.tuple.srcIp, pkt.tuple.dstIp)) % lbs.size();
                    lbs.get(lbIdx).queue().put(pkt);
                }

                System.out.println("[Reader] Done reading " + pktId + " packets");

                // Graceful pipeline shutdown
                Thread.sleep(500);
                lbs.forEach(LoadBalancer::stop);
                fps.forEach(FastPath::stop);
                outputRunning.set(false);

                outputFuture.get();
                threadPool.shutdown();

                printReport();
                return true;
            }
        } catch (Exception e) {
            System.err.println("Execution exception: " + e.getMessage());
            return false;
        }
    }

    private void printReport() {
        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Total Packets:      %12d                               ║\n", stats.totalPackets.get());
        System.out.printf("║ Total Bytes:        %12d                               ║\n", stats.totalBytes.get());
        System.out.printf("║ TCP Packets:        %12d                               ║\n", stats.tcpPackets.get());
        System.out.printf("║ UDP Packets:        %12d                               ║\n", stats.udpPackets.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf("║ Forwarded:          %12d                               ║\n", stats.forwarded.get());
        System.out.printf("║ Dropped:            %12d                               ║\n", stats.dropped.get());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║ THREAD STATISTICS                                            ║");
        for (int i = 0; i < lbs.size(); i++) {
            System.out.printf("║    LB%d dispatched:    %12d                               ║\n", i, lbs.get(i).dispatched());
        }
        for (int i = 0; i < fps.size(); i++) {
            System.out.printf("║    FP%d processed:     %12d                               ║\n", i, fps.get(i).processed());
        }
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                    APPLICATION BREAKDOWN                     ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        long total = stats.totalPackets.get();
        List<Map.Entry<AppType, Long>> sortedApps = new ArrayList<>(stats.appCounts.entrySet());
        sortedApps.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        for (Map.Entry<AppType, Long> entry : sortedApps) {
            long count = entry.getValue();
            if (count == 0) continue;
            double pct = total > 0 ? (100.0 * count / total) : 0;
            int barLen = (int) (pct / 5);
            String barStr = "#".repeat(barLen) + " ".repeat(20 - barLen);

            System.out.printf("║ %-15s %8d  %5.1f%%  %-20s ║\n", entry.getKey().toString(), count, pct, barStr);
        }
        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        if (!stats.detectedSnis.isEmpty()) {
            System.out.println("\n[Detected Domains/SNIs]");
            stats.detectedSnis.forEach((sni, app) -> System.out.println("  - " + sni + " -> " + app.toString()));
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("\nUsage: java dpi.DPIEngine <input.pcap> <output.pcap> [options]");
            System.exit(1);
        }

        String input = args[0];
        String output = args[1];
        Config cfg = new Config();

        List<String> blockIps = new ArrayList<>();
        List<String> blockApps = new ArrayList<>();
        List<String> blockDomains = new ArrayList<>();

        for (int i = 2; i < args.length; i++) {
            String arg = args[i];
            if (arg.equals("--block-ip") && i + 1 < args.length) blockIps.add(args[++i]);
            else if (arg.equals("--block-app") && i + 1 < args.length) blockApps.add(args[++i]);
            else if (arg.equals("--block-domain") && i + 1 < args.length) blockDomains.add(args[++i]);
            else if (arg.equals("--lbs") && i + 1 < args.length) cfg.numLbs = Integer.parseInt(args[++i]);
            else if (arg.equals("--fps") && i + 1 < args.length) cfg.fps_per_lb = Integer.parseInt(args[++i]);
        }

        DPIEngine engine = new DPIEngine(cfg);
        blockIps.forEach(engine::blockIP);
        blockApps.forEach(engine::blockApp);
        blockDomains.forEach(engine::blockDomain);

        engine.process(input, output);
    }
}
