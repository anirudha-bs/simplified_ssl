package security;

import java.io.*;
import java.math.BigInteger;
import java.util.Random;

public class RSA {

    // Encryption method overloaded for String input
    public static byte[] cipher(String input, Key key) throws Exception {
        return cipher(input.getBytes(), key);
    }

    // Encryption method
    public static byte[] cipher(byte[] input, Key key) throws Exception {
        byte[] paddedInput = new byte[input.length + 1];
        paddedInput[0] = 0;
        System.arraycopy(input, 0, paddedInput, 1, input.length);
        BigInteger encrypted = new BigInteger(paddedInput).modPow(key.getKey(), key.getN());
        if (encrypted.toByteArray()[0] != 0) {
            return encrypted.toByteArray();
        }
        byte[] encryptedBytes = new byte[encrypted.toByteArray().length - 1];
        System.arraycopy(encrypted.toByteArray(), 1, encryptedBytes, 0, encryptedBytes.length);
        return encryptedBytes;
    }

    // Generate public-private key pair
    public static KeyPair generateKeys(BigInteger p, BigInteger q) {
        BigInteger n = p.multiply(q);
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = relativePrime(phiN);
        BigInteger d = e.modInverse(phiN);
        return new KeyPair(new PrivateKey(d, n), new PublicKey(e, n));
    }

    // Main method
    public static void main(String[] args) throws Exception {
        if (args.length >= 1) {
            if (args[0].equals("-help")) {
                System.out.println("java security.RSA -help");
                System.out.println("   - this message\n");
                System.out.println("java security.RSA -gen [ <text> ]");
                System.out.println("   - generate private (KR) and public (KU) keys");
                System.out.println("     and test them on <text> (optional)\n");
                return;
            }
            if (args[0].equals("-gen") && args.length <= 2) {
                int primeSize = Integer.parseInt(System.getProperty("prime_size", "256"));
                int primeCertainty = Integer.parseInt(System.getProperty("prime_certainty", "5"));
                BigInteger p = new BigInteger(primeSize, primeCertainty, new Random());
                BigInteger q = new BigInteger(primeSize, primeCertainty, new Random());
                KeyPair keyPair = generateKeys(p, q);
                System.out.println(keyPair);
                if (args.length == 2) {
                    byte[] inputBytes = args[1].getBytes();
                    byte[] encryptedWithPublic = cipher(inputBytes, keyPair.getPublicKey());
                    byte[] decryptedWithPrivate = cipher(inputBytes, keyPair.getPrivateKey());
                    System.out.println("KU(KR(M))=" + new String(cipher(encryptedWithPublic, keyPair.getPrivateKey())));
                    System.out.println("KR(KU(M))=" + new String(cipher(decryptedWithPrivate, keyPair.getPublicKey())));
                }
                return;
            }
        }
        System.out.println("java security.RSA -help");
    }

    // Find a number that is relatively prime to phiN
    private static BigInteger relativePrime(BigInteger phiN) {
        Random random = new Random();
        int length = phiN.toByteArray().length;
        BigInteger one = BigInteger.ONE;
        BigInteger candidate;
        do {
            byte[] candidateBytes = new byte[length];
            random.nextBytes(candidateBytes);
            candidate = new BigInteger(candidateBytes).abs();
            candidate = candidate.mod(phiN);
        } while (phiN.gcd(candidate).compareTo(one) != 0);
        return candidate;
    }

    // Key class
    public static class Key {
        protected BigInteger key;
        protected BigInteger n;

        public Key() {
            this(BigInteger.ZERO, BigInteger.ZERO);
        }

        public Key(BigInteger key, BigInteger n) {
            this.key = key;
            this.n = n;
        }

        protected BigInteger getKey() {
            return key;
        }

        protected BigInteger getN() {
            return n;
        }

        // Read key from input stream
        public void read(InputStream inputStream) throws IOException {
            StringBuilder keyBuilder = new StringBuilder();
            int byteRead;
            while ((byteRead = inputStream.read()) != '{') {
                switch (byteRead) {
                    case -1:
                        throw new EOFException("Unexpected End of File");
                    case 9:
                    case 10:
                    case 13:
                    case 32:
                        break;
                    default:
                        throw new IOException("Wrong Format");
                }
            }
            while ((byteRead = inputStream.read()) != ',') {
                if (byteRead == -1) {
                    throw new EOFException("Unexpected End of File");
                }
                keyBuilder.append((char) byteRead);
            }
            try {
                key = new BigInteger(keyBuilder.toString());
            } catch (NumberFormatException e) {
                throw new IOException(e.toString());
            }
            keyBuilder.setLength(0);
            while ((byteRead = inputStream.read()) != '}') {
                if (byteRead == -1) {
                    throw new EOFException("Unexpected End of File");
                }
                keyBuilder.append((char) byteRead);
            }
            try {
                n = new BigInteger(keyBuilder.toString());
            } catch (NumberFormatException e) {
                throw new IOException(e.toString());
            }
        }

        // Read key from byte array
        public void read(byte[] bytes) throws IOException {
            read(new ByteArrayInputStream(bytes));
        }

        // Convert key to string
        public String toString() {
            return "{" + key.toString() + ',' + n.toString() + '}';
        }
    }

    // Public key class
    public static class PublicKey extends RSA.Key {
        public PublicKey(InputStream inputStream) throws IOException {
            read(inputStream);
        }

        protected PublicKey(BigInteger key, BigInteger n) {
            super(key, n);
        }

        public PublicKey(byte[] bytes) throws IOException {
            read(bytes);
        }
    }

    // Private key class
    public static class PrivateKey extends RSA.Key {
        public PrivateKey(InputStream inputStream) throws IOException {
            read(inputStream);
        }

        protected PrivateKey(BigInteger key, BigInteger n) {
            super(key, n);
        }

        public PrivateKey(byte[] bytes) throws IOException {
            read(bytes);
        }
    }

    // Key pair class
    public static class KeyPair {
        private RSA.PrivateKey privateKey;
        private RSA.PublicKey publicKey;

        public KeyPair(RSA.PrivateKey privateKey, RSA.PublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public RSA.PrivateKey getPrivateKey() {
            return privateKey;
        }

        public RSA.PublicKey getPublicKey() {
            return publicKey;
        }

        public String toString() {
            return "KR=" + privateKey + System.getProperty("line.separator") + "KU=" + publicKey;
        }
    }
}
