package dpi;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class SNIExtractor {

    // Constants for TLS parsing
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int EXTENSION_SNI = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    private static int readUint16BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static int readUint24BE(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 16) | ((data[offset + 1] & 0xFF) << 8) | (data[offset + 2] & 0xFF);
    }

    public static boolean isTLSClientHello(byte[] payload, int length) {
        if (length < 9) return false;

        // Check TLS record header: Content Type (0x16 = Handshake)
        if ((payload[0] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // Bytes 1-2: TLS Version (0x0300 to 0x0304)
        int version = readUint16BE(payload, 1);
        if (version < 0x0300 || version > 0x0304) return false;

        // Bytes 3-4: Record length
        int recordLength = readUint16BE(payload, 3);
        if (recordLength > length - 5) return false;

        // Check handshake header (starts at byte 5): Handshake Type (0x01 = Client Hello)
        if ((payload[5] & 0xFF) != HANDSHAKE_CLIENT_HELLO) return false;

        return true;
    }

    public static String extractTLS(byte[] payload, int length) {
        if (!isTLSClientHello(payload, length)) {
            return null;
        }

        int offset = 5; // Skip TLS record header
        int handshakeLength = readUint24BE(payload, offset + 1);
        offset += 4;    // Skip handshake header

        offset += 2;    // Client version
        offset += 32;   // Random bytes

        if (offset >= length) return null;
        int sessionIdLength = payload[offset] & 0xFF;
        offset += 1 + sessionIdLength;

        if (offset + 2 > length) return null;
        int cipherSuitesLength = readUint16BE(payload, offset);
        offset += 2 + cipherSuitesLength;

        if (offset >= length) return null;
        int compressionMethodsLength = payload[offset] & 0xFF;
        offset += 1 + compressionMethodsLength;

        if (offset + 2 > length) return null;
        int extensionsLength = readUint16BE(payload, offset);
        offset += 2;

        int extensionsEnd = offset + extensionsLength;
        if (extensionsEnd > length) {
            extensionsEnd = length; 
        }

        // Parse extensions to find SNI
        while (offset + 4 <= extensionsEnd) {
            int extensionType = readUint16BE(payload, offset);
            int extensionLength = readUint16BE(payload, offset + 2);
            offset += 4;

            if (offset + extensionLength > extensionsEnd) break;

            if (extensionType == EXTENSION_SNI) {
                if (extensionLength < 5) break;

                int sniListLength = readUint16BE(payload, offset);
                if (sniListLength < 3) break;

                int sniType = payload[offset + 2] & 0xFF;
                int sniLength = readUint16BE(payload, offset + 3);

                if (sniType != SNI_TYPE_HOSTNAME) break;
                if (sniLength > extensionLength - 5) break;

                // Extract and return the hostname
                return new String(payload, offset + 5, sniLength, StandardCharsets.US_ASCII);
            }

            offset += extensionLength;
        }

        return null;
    }

    // ============================================================================
    // HTTP Host Header Extractor Implementation
    // ============================================================================
    public static class HTTPHostExtractor {
        public static boolean isHTTPRequest(byte[] payload, int length) {
            if (length < 4) return false;

            String prefix = new String(payload, 0, 4, StandardCharsets.US_ASCII);
            return prefix.startsWith("GET ") || prefix.startsWith("POST") || 
                   prefix.startsWith("PUT ") || prefix.startsWith("HEAD") || 
                   prefix.startsWith("DELE") || prefix.startsWith("PATC") || 
                   prefix.startsWith("OPTI");
        }

        public static String extract(byte[] payload, int length) {
            if (!isHTTPRequest(payload, length)) {
                return null;
            }

            String fullPayload = new String(payload, 0, length, StandardCharsets.US_ASCII);
            String[] lines = fullPayload.split("\r\n");

            for (String line : lines) {
                if (line.regionMatches(true, 0, "Host:", 0, 5)) {
                    String host = line.substring(5).trim();
                    
                    // Remove port if present
                    int colonPos = host.indexOf(':');
                    if (colonPos != -1) {
                        host = host.substring(0, colonPos);
                    }
                    return host;
                }
            }
            return null;
        }
    }

    // ============================================================================
    // DNS Extractor Implementation
    // ============================================================================
    public static class DNSExtractor {
        public static boolean isDNSQuery(byte[] payload, int length) {
            if (length < 12) return false;

            // Check QR bit (byte 2, bit 7) - should be 0 for query
            int flags = payload[2] & 0xFF;
            if ((flags & 0x80) != 0) return false;

            // Check QDCOUNT (bytes 4-5) - should be > 0
            int qdcount = ((payload[4] & 0xFF) << 8) | (payload[5] & 0xFF);
            return qdcount > 0;
        }

        public static String extractQuery(byte[] payload, int length) {
            if (!isDNSQuery(payload, length)) {
                return null;
            }

            int offset = 12;
            StringBuilder domain = new StringBuilder();

            while (offset < length) {
                int labelLength = payload[offset] & 0xFF;

                if (labelLength == 0) break; // End of domain name
                if (labelLength > 63) break;  // Compression pointer or invalid

                offset++;
                if (offset + labelLength > length) break;

                if (domain.length() > 0) {
                    domain.append('.');
                }
                domain.append(new String(payload, offset, labelLength, StandardCharsets.US_ASCII));
                offset += labelLength;
            }

            return domain.length() == 0 ? null : domain.toString();
        }
    }

    // ============================================================================
    // QUIC SNI Extractor Implementation
    // ============================================================================
    public static class QUICSNIExtractor {
        public static boolean isQUICInitial(byte[] payload, int length) {
            if (length < 5) return false;
            return (payload[0] & 0x80) != 0; // Check form bit
        }

        public static String extract(byte[] payload, int length) {
            if (!isQUICInitial(payload, length)) {
                return null;
            }

            // Simplified search for embedded Client Hello within raw QUIC payload
            for (int i = 0; i + 50 < length; i++) {
                if (payload[i] == 0x01) { // Handshake Type: Client Hello
                    byte[] subPayload = new byte[length - i + 5];
                    System.arraycopy(payload, i - 5, subPayload, 0, subPayload.length);
                    String result = extractTLS(subPayload, subPayload.length);
                    if (result != null) return result;
                }
            }

            return null;
        }
    }
}
