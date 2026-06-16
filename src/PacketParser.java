package dpi;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PacketParser {

    public boolean parse(PcapReader.RawPacket raw, ParsedPacket parsed) {
        if (raw == null || raw.data == null) {
            return false;
        }

        parsed.timestampSec = raw.header.tsSec;
        parsed.timestampUsec = raw.header.tsUsec;

        byte[] data = raw.data;
        int len = data.length;
        int[] offset = {0}; // Emulate reference tracking via mutable array

        // 1. Parse Ethernet Layer
        if (!parseEthernet(data, len, parsed, offset)) {
            return false;
        }

        // 2. Parse IP Layer if it's an IPv4 packet
        if (parsed.etherType == ParsedPacket.EtherType.IPv4) {
            if (!parseIPv4(data, len, parsed, offset)) {
                return false;
            }

            // 3. Parse Transport Layer based on protocol
            if (parsed.protocol == ParsedPacket.Protocol.TCP) {
                if (!parseTCP(data, len, parsed, offset)) {
                    return false;
                }
            } else if (parsed.protocol == ParsedPacket.Protocol.UDP) {
                if (!parseUDP(data, len, parsed, offset)) {
                    return false;
                }
            }
        }

        // 4. Extract Payload Data
        if (offset[0] < len) {
            parsed.payloadLength = len - offset[0];
            parsed.payloadData = new byte[parsed.payloadLength];
            System.arraycopy(data, offset[0], parsed.payloadData, 0, parsed.payloadLength);
        } else {
            parsed.payloadLength = 0;
            parsed.payloadData = null;
        }

        return true;
    }

    private boolean parseEthernet(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int ETH_HEADER_LEN = 14;
        if (len < ETH_HEADER_LEN) {
            return false;
        }

        // Parse destination MAC (bytes 0-5) and source MAC (bytes 6-11)
        parsed.destMac = macToString(data, 0);
        parsed.srcMac = macToString(data, 6);

        // Parse EtherType (bytes 12-13, big-endian)
        ByteBuffer buffer = ByteBuffer.wrap(data, 12, 2).order(ByteOrder.BIG_ENDIAN);
        parsed.etherType = Short.toUnsignedInt(buffer.getShort());

        offset[0] = ETH_HEADER_LEN;
        return true;
    }

    private boolean parseIPv4(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int MIN_IP_HEADER_LEN = 20;
        if (len < offset[0] + MIN_IP_HEADER_LEN) {
            return false;
        }

        int ipStart = offset[0];
        int versionIhl = Byte.toUnsignedInt(data[ipStart]);
        parsed.ipVersion = (versionIhl >> 4) & 0x0F;
        int ihl = versionIhl & 0x0F;

        if (parsed.ipVersion != 4) {
            return false;
        }

        int ipHeaderLen = ihl * 4;
        if (ipHeaderLen < MIN_IP_HEADER_LEN || len < offset[0] + ipHeaderLen) {
            return false;
        }

        parsed.ttl = Byte.toUnsignedInt(data[ipStart + 8]);
        parsed.protocol = Byte.toUnsignedInt(data[ipStart + 9]);

        // Extract Source and Destination IP Address bytes
        parsed.srcIp = ipToString(data, ipStart + 12);
        parsed.destIp = ipToString(data, ipStart + 16);

        parsed.hasIp = true;
        offset[0] += ipHeaderLen;
        return true;
    }

    private boolean parseTCP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int MIN_TCP_HEADER_LEN = 20;
        if (len < offset[0] + MIN_TCP_HEADER_LEN) {
            return false;
        }

        int tcpStart = offset[0];
        ByteBuffer buffer = ByteBuffer.wrap(data, tcpStart, MIN_TCP_HEADER_LEN).order(ByteOrder.BIG_ENDIAN);

        parsed.srcPort = Short.toUnsignedInt(buffer.getShort());
        parsed.destPort = Short.toUnsignedInt(buffer.getShort());
        parsed.seqNumber = Integer.toUnsignedLong(buffer.getInt());
        parsed.ackNumber = Integer.toUnsignedLong(buffer.getInt());

        int dataOffsetByte = Byte.toUnsignedInt(data[tcpStart + 12]);
        int dataOffset = (dataOffsetByte >> 4) & 0x0F;
        int tcpHeaderLen = dataOffset * 4;

        parsed.tcpFlags = Byte.toUnsignedInt(data[tcpStart + 13]);

        if (tcpHeaderLen < MIN_TCP_HEADER_LEN || len < offset[0] + tcpHeaderLen) {
            return false;
        }

        parsed.hasTcp = true;
        offset[0] += tcpHeaderLen;
        return true;
    }

    private boolean parseUDP(byte[] data, int len, ParsedPacket parsed, int[] offset) {
        int UDP_HEADER_LEN = 8;
        if (len < offset[0] + UDP_HEADER_LEN) {
            return false;
        }

        int udpStart = offset[0];
        ByteBuffer buffer = ByteBuffer.wrap(data, udpStart, UDP_HEADER_LEN).order(ByteOrder.BIG_ENDIAN);

        parsed.srcPort = Short.toUnsignedInt(buffer.getShort());
        parsed.destPort = Short.toUnsignedInt(buffer.getShort());

        parsed.hasUdp = true;
        offset[0] += UDP_HEADER_LEN;
        return true;
    }

    public static String macToString(byte[] data, int startOffset) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02x", data[startOffset + i]));
        }
        return sb.toString();
    }

    public static String ipToString(byte[] data, int startOffset) {
        return String.format("%d.%d.%d.%d",
                Byte.toUnsignedInt(data[startOffset]),
                Byte.toUnsignedInt(data[startOffset + 1]),
                Byte.toUnsignedInt(data[startOffset + 2]),
                Byte.toUnsignedInt(data[startOffset + 3]));
    }

    public static String protocolToString(int protocol) {
        if (protocol == ParsedPacket.Protocol.ICMP) return "ICMP";
        if (protocol == ParsedPacket.Protocol.TCP) return "TCP";
        if (protocol == ParsedPacket.Protocol.UDP) return "UDP";
        return "Unknown(" + protocol + ")";
    }

    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & ParsedPacket.TCPFlags.SYN) != 0) sb.append("SYN ");
        if ((flags & ParsedPacket.TCPFlags.ACK) != 0) sb.append("ACK ");
        if ((flags & ParsedPacket.TCPFlags.FIN) != 0) sb.append("FIN ");
        if ((flags & ParsedPacket.TCPFlags.RST) != 0) sb.append("RST ");
        if ((flags & ParsedPacket.TCPFlags.PSH) != 0) sb.append("PSH ");
        if ((flags & ParsedPacket.TCPFlags.URG) != 0) sb.append("URG ");
        
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }
}
