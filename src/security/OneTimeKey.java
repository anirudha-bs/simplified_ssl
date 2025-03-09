package security;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Random;

public class OneTimeKey {
    // Main method to demonstrate one-time key encryption and decryption
    public static void main(String[] args) throws Exception {
        // Check if command line arguments are provided correctly
        if (args.length < 2) {
            System.out.println("java security.OneTimeKey <key>  <text> [ <text> ... ]");
            System.exit(1);
        }

        // Extract key from command line arguments
        byte[] key = args[0].getBytes();

        // Iterate over input texts for encryption and decryption
        for (int i = 1; i < args.length; i++) {
            System.out.println("The Original text is " + args[i]);
            // Encrypt text using one-time key
            byte[] encodedText = xor(args[i].getBytes(), key);
            System.out.println("Encoded into " + new String(encodedText));
            // Decrypt text using the same one-time key
            byte[] decodedText = xor(encodedText, key);
            System.out.println("Decoded into " + new String(decodedText));
        }
    }

    // Method to generate a new one-time key
    public static byte[] newKey(int length) {
        return newKey(new Random(), length);
    }

    // Method to generate a new one-time key using a specific random number generator
    public static byte[] newKey(Random random, int length) {
        byte[] key = new byte[length];
        random.nextBytes(key);
        return key;
    }

    // Method to print the key bytes to an output stream
    public static void printKey(byte[] key, OutputStream outputStream) throws IOException {
        for (int i = 0; i < key.length; i++)
            outputStream.write(key[i]);
    }

    // Method to perform bitwise XOR operation between two byte arrays
    public static byte[] xor(byte[] data, byte[] key) {
        // Check if the length of data is a multiple of the length of the key
        if (data.length % key.length != 0) {
            throw new RuntimeException("ERROR in Length of one-time key !!!");
        }
        // Create a new byte array to store the result
        byte[] result = new byte[data.length];
        // Copy data to the result array
        System.arraycopy(data, 0, result, 0, data.length);

        int index = 0;

        // Iterate over data segments, each equal to the length of the key
        for (int i = 0; i < data.length / key.length; i++) {
            // Iterate over each byte in the key
            for (int j = 0; j < key.length; j++) {
                // Perform XOR operation between corresponding bytes of data and key
                result[index] = (byte) (result[index] ^ key[j]);
                index++;
            }
        }
        return result;
    }
}
