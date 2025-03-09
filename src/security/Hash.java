package security;

import java.io.PrintStream;
import java.math.BigInteger;

public class Hash {
    private int dataBytes;
    private int checkBytes;
    private byte pattern;
    private int k;

    public Hash(int dataBytes, int checkBytes, byte pattern, int k) {
        this.dataBytes = dataBytes;
        this.checkBytes = checkBytes;
        this.pattern = pattern;
        this.k = k;
    }

    public int getNumberOfDataBytes() {
        return this.dataBytes;
    }

    public int getPacketSize() {
        return this.dataBytes + this.checkBytes + 1;
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 5) {
            System.out.println("java security.Hash <dataBytes> <checkBytes> <pattern> <k> <text> [ <text> ... ]");
            System.exit(1);
        }

        int dataBytes = Integer.parseInt(args[0]);
        int checkBytes = Integer.parseInt(args[1]);
        byte pattern = (byte) Integer.parseInt(args[2]);
        int k = Integer.parseInt(args[3]);

        for (int i = 4; i < args.length; i++) {
            byte[] packedBytes = pack(args[i].getBytes(), dataBytes, checkBytes, pattern, k);
            System.out.println("Packed Bytes:");
            System.out.println(new String(packedBytes));
            System.out.println("Unpacked Bytes:");
            System.out.println(new String(unpack(packedBytes, dataBytes, checkBytes, pattern, k)));
        }
    }

    public byte[] pack(byte[] data) {
        return pack(data, this.dataBytes, this.checkBytes, this.pattern, this.k);
    }

    public static byte[] pack(byte[] data, int dataBytes, int checkBytes, byte pattern, int k) {
        if (dataBytes > 256) {
            throw new RuntimeException("DataBytes MAX Size is 255.");
        }

        int length = data.length;
        int packetSize = dataBytes + checkBytes + 1;
        int numPackets = length % dataBytes == 0 ? length / dataBytes : length / dataBytes + 1;

        byte[] packedData = new byte[numPackets * packetSize];
        int dataIndex = 0;

        for (int packetIndex = 0; packetIndex < numPackets; packetIndex++) {
            byte dataSize = (byte) ((packetIndex + 1) * dataBytes > length ? length % dataBytes : dataBytes);
            packedData[packetIndex * packetSize] = dataSize;

            BigInteger checksum = BigInteger.ZERO;

            for (int i = 0; i < dataSize; i++) {
                byte b = data[dataIndex++];
                checksum = checksum.add(BigInteger.valueOf((pattern & b) * k));
                packedData[packetIndex * packetSize + i + 1] = b;
            }

            checksum = checksum.mod(BigInteger.valueOf((int) Math.pow(2.0, 8 * checkBytes)));
            byte checksumSize = (byte) checksum.toByteArray().length;

            for (int i = 0; i < checkBytes; i++) {
                byte checksumByte;
                if (checkBytes - i > checksumSize) {
                    checksumByte = 0;
                } else {
                    checksumByte = checksum.toByteArray()[i - (checkBytes - checksumSize)];
                }
                packedData[packetIndex * packetSize + dataBytes + i + 1] = checksumByte;
            }
        }
        return packedData;
    }

    public byte[] unpack(byte[] packedData) throws Exception {
        return unpack(packedData, this.dataBytes, this.checkBytes, this.pattern, this.k);
    }

    public static byte[] unpack(byte[] packedData, int dataBytes, int checkBytes, byte pattern, int k) throws Exception {
        if (dataBytes > 256) {
            throw new RuntimeException("DataBytes MAX Size is 255");
        }

        int length = packedData.length;
        int packetSize = 1 + dataBytes + checkBytes;

        if (length % packetSize != 0) {
            throw new Exception("Wrong Packet Size !!!");
        }

        int numPackets = length / packetSize;
        int expectedLength = 0;

        for (int packetIndex = 0; packetIndex < numPackets; packetIndex++) {
            expectedLength += packedData[packetIndex * packetSize];
        }

        byte[] unpackedData = new byte[expectedLength];
        int unpackedIndex = 0;

        for (int packetIndex = 0; packetIndex < numPackets; packetIndex++) {
            int dataSize = packedData[packetIndex * packetSize];
            BigInteger checksum = BigInteger.ZERO;
            int dataIndex = packetIndex * packetSize + 1;

            for (int i = 0; i < dataSize; i++) {
                byte b = packedData[dataIndex++];
                checksum = checksum.add(BigInteger.valueOf((b & pattern) * k));
                unpackedData[unpackedIndex++] = b;
            }

            if (dataSize < dataBytes) {
                dataIndex += dataBytes - dataSize;
            }

            checksum = checksum.mod(BigInteger.valueOf((int) Math.pow(2.0, 8 * checkBytes)));
            byte checksumSize = (byte) checksum.toByteArray().length;

            for (int i = checkBytes - checksumSize; i < checkBytes; i++) {
                int expectedChecksum = packedData[packetIndex * packetSize + dataBytes + i + 1];
                int actualChecksum = checksum.toByteArray()[checksumSize - checkBytes + i];
                if (expectedChecksum != actualChecksum) {
                    throw new Exception("Checksum ERROR !!!");
                }
            }
        }
        return unpackedData;
    }
}
