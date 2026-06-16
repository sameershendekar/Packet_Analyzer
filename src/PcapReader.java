package dpi;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

public class PcapReader implements AutoCloseable {

    // Magic numbers for PCAP files
    private static final int PCAP_MAGIC_NATIVE = 0xa1b2c3d4;
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

    // Inner classes representing headers and structures
    public static class PcapGlobalHeader {
        public int magicNumber;
        public short versionMajor;
        public short versionMinor;
        public int thiszone;
        public int sigfigs;
        public int snaplen;
        public int network;
    }

    public static class PcapPacketHeader {
        public int tsSec;
        public int tsUsec;
        public int inclLen;
        public int origLen;
    }

    public static class RawPacket {
        public PcapPacketHeader header = new PcapPacketHeader();
        public byte[] data = new byte[0];
    }

    private FileInputStream fileStream;
    private final PcapGlobalHeader globalHeader = new PcapGlobalHeader();
    private ByteOrder byteOrder = ByteOrder.BIG_ENDIAN;

    public boolean open(String filename) {
        close();
        try {
            fileStream = new FileInputStream(filename);

            // Read the 24-byte global header
            byte[] headerBytes = new byte[24];
            int read = fileStream.read(headerBytes);
            if (read < 24) {
                System.err.println("Error: Could not read PCAP global header");
                close();
                return false;
            }

            // Wrap and check magic number to handle Indianness / Byte Swap
            ByteBuffer buffer = ByteBuffer.wrap(headerBytes);
            buffer.order(ByteOrder.BIG_ENDIAN);
            int magic = buffer.getInt();

            if (magic == PCAP_MAGIC_NATIVE) {
                this.byteOrder = ByteOrder.BIG_ENDIAN;
            } else if (magic == PCAP_MAGIC_SWAPPED) {
                this.byteOrder = ByteOrder.LITTLE_ENDIAN;
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%x\n", magic);
                close();
                return false;
            }

            // Reparse using correct byte order
            buffer.order(this.byteOrder);
            buffer.position(0);

            globalHeader.magicNumber = buffer.getInt();
            globalHeader.versionMajor = buffer.getShort();
            globalHeader.versionMinor = buffer.getShort();
            globalHeader.thiszone = buffer.getInt();
            globalHeader.sigfigs = buffer.getInt();
            globalHeader.snaplen = buffer.getInt();
            globalHeader.network = buffer.getInt();

            System.out.println("Opened PCAP file: " + filename);
            System.out.println("  Version: " + globalHeader.versionMajor + "." + globalHeader.versionMinor);
            System.out.println("  Snaplen: " + globalHeader.snaplen + " bytes");
            System.out.println("  Link type: " + globalHeader.network + (globalHeader.network == 1 ? " (Ethernet)" : ""));

            return true;

        } catch (IOException e) {
            System.err.println("Error: Could not open file: " + filename);
            return false;
        }
    }

    public void close() {
        if (fileStream != null) {
            try {
                fileStream.close();
            } catch (IOException ignored) {}
            fileStream = null;
        }
    }

    public boolean readNextPacket(RawPacket packet) {
        if (fileStream == null) {
            return false;
        }

        try {
            // Read 16-byte packet header
            byte[] headerBytes = new byte[16];
            int read = fileStream.read(headerBytes);
            if (read < 16) {
                return false; // EOF or error
            }

            ByteBuffer buffer = ByteBuffer.wrap(headerBytes).order(byteOrder);
            packet.header.tsSec = buffer.getInt();
            packet.header.tsUsec = buffer.getInt();
            packet.header.inclLen = buffer.getInt();
            packet.header.origLen = buffer.getInt();

            // Sanity check on packet length
            if (packet.header.inclLen > globalHeader.snaplen || packet.header.inclLen > 65535) {
                System.err.println("Error: Invalid packet length: " + packet.header.inclLen);
                return false;
            }

            // Read raw packet data
            packet.data = new byte[packet.header.inclLen];
            int dataRead = fileStream.read(packet.data);
            if (dataRead < packet.header.inclLen) {
                System.err.println("Error: Could not read packet data");
                return false;
            }

            return true;

        } catch (IOException e) {
            System.err.println("Error: Exception encountered while reading packet data");
            return false;
        }
    }
}
