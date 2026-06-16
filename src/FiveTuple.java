package dpi;

public class FiveTuple {
    public int srcIp;
    public int dstIp;
    public int srcPort;
    public int dstPort;
    public int protocol;

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    private String formatIP(int ip) {
        return String.format("%d.%d.%d.%d",
                (ip & 0xFF),
                ((ip >> 8) & 0xFF),
                ((ip >> 16) & 0xFF),
                ((ip >> 24) & 0xFF));
    }

    @Override
    public String toString() {
        String protoStr = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
        return String.format("%s:%d -> %s:%d (%s)",
                formatIP(srcIp), srcPort,
                formatIP(dstIp), dstPort,
                protoStr);
    }
}
