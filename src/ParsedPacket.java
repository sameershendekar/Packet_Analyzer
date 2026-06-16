package dpi;

public class ParsedPacket {
    public int timestampSec;
    public int timestampUsec;
    
    public String srcMac = "";
    public String destMac = "";
    public int etherType;
    
    public boolean hasIp = false;
    public int ipVersion;
    public int ttl;
    public int protocol;
    public String srcIp = "";
    public String destIp = "";
    
    public boolean hasTcp = false;
    public boolean hasUdp = false;
    public int srcPort;
    public int destPort;
    public long seqNumber;
    public long ackNumber;
    public int tcpFlags;
    
    public int payloadLength;
    public byte[] payloadData = null;

    // Constants mirroring the original C++ header structures
    public static class EtherType {
        public static final int IPv4 = 0x0800;
    }

    public static class Protocol {
        public static final int ICMP = 1;
        public static final int TCP = 6;
        public static final int UDP = 17;
    }

    public static class TCPFlags {
        public static final int FIN = 0x01;
        public static final int SYN = 0x02;
        public static final int RST = 0x04;
        public static final int PSH = 0x08;
        public static final int ACK = 0x10;
        public static final int URG = 0x20;
    }
}
