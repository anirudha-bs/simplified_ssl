import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;
import security.Hash;
import security.OneTimeKey;
import security.RSA;
import security.SSLSocket;

public class Client {

    private SSLSocket sslSocket;

    public Client(String host, int port, String name) throws Exception {
        // Load properties from file
        Properties properties = new Properties();
        try (FileInputStream fileInputStream = new FileInputStream(name + ".txt")) {
            properties.load(fileInputStream);
        }

        // Retrieve necessary properties
        String company = properties.getProperty("company");
        RSA.PublicKey serverPublicKey = new RSA.PublicKey(properties.getProperty("server.public_key").getBytes());
        RSA.PrivateKey privateKey = new RSA.PrivateKey(properties.getProperty("private_key").getBytes());
        byte pattern = (byte) Integer.parseInt(properties.getProperty("pattern"));
        int ndatabytes = Integer.parseInt(properties.getProperty("ndatabytes"));
        int ncheckbytes = Integer.parseInt(properties.getProperty("ncheckbytes"));
        int k = Integer.parseInt(properties.getProperty("k"));

        // Create Hash object
        Hash hash = new Hash(ndatabytes, ncheckbytes, pattern, k);

        // Encrypt company name with private key
        byte[] encryptedCompanyName = RSA.cipher(company.getBytes(), privateKey);

        // Generate one-time key
        byte[] oneTimeKey = OneTimeKey.newKey(ndatabytes + ncheckbytes + 1);

        // Encrypt one-time key with server's public key
        byte[] encryptedOneTimeKey = RSA.cipher(oneTimeKey, serverPublicKey);

        // Encrypt name with server's public key
        byte[] encryptedName = RSA.cipher(name.getBytes(), serverPublicKey);

        // Initialize SSLSocket
        sslSocket = new SSLSocket(host, port, encryptedName, encryptedCompanyName, encryptedOneTimeKey, oneTimeKey, hash);
    }

    public void execute() throws Exception {
        int bytesWritten = 0;
        int bytesRead = 0;
        int data;
        // Read data from standard input and write to SSLSocket output stream
        while ((data = System.in.read()) != -1) {
            sslSocket.getOutputStream().write(data);
            if (((char) data == '\n') || ((char) data == '\r')) {
                sslSocket.getOutputStream().flush();
            }
            bytesWritten++;
        }
        sslSocket.getOutputStream().flush();

        // Read data from SSLSocket input stream and write to standard output
        while ((data = sslSocket.getInputStream().read()) != -1) {
            System.out.write(data);
            bytesRead++;
        }

        // Display summary
        System.out.println();
        System.out.println("Wrote " + bytesWritten + " bytes");
        System.out.println("Read " + bytesRead + " bytes");
        sslSocket.close();
    }

    public static void main(String[] args) throws Exception {
        // Check command line arguments
        if (args.length != 3) {
            System.out.println("Usage: java Client <host> <port> <name>");
            System.exit(1);
        }
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String name = args[2];
        new Client(host, port, name).execute();
    }
}
