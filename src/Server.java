import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

import security.RSA;
import security.SSLServerSocket;
import security.SSLSocket;

public class Server implements Runnable {
    private RSA.PrivateKey serverPrivateKey;
    private Properties properties;
    private SSLServerSocket serverSocket;
    private int port;

    public Server() throws Exception {
        // Load server private key
        String privateKeyFile = System.getProperty("server.private_key", "private_key.txt");
        try (FileInputStream fileInputStream = new FileInputStream(privateKeyFile)) {
            serverPrivateKey = new RSA.PrivateKey(fileInputStream);
        }

        // Load user properties
        String usersFile = System.getProperty("server.users", "users.txt");
        try (FileInputStream fileInputStream = new FileInputStream(usersFile)) {
            properties = new Properties();
            properties.load(fileInputStream);
        }

        // Set server port
        String portString = System.getProperty("server.port");
        port = (portString != null) ? Integer.parseInt(portString) : 5000;

        // Create SSL server socket
        serverSocket = new SSLServerSocket(port, serverPrivateKey, properties);
    }

    public static void main(String[] args) throws Exception {
        new Server().run();
    }

    @Override
    public void run() {
        while (true) {
            try {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                new Thread(new RequestHandler(clientSocket)).start();
            } catch (Exception e) {
                System.out.println("SERVER: " + e);
            }
        }
    }

    public class RequestHandler implements Runnable {
        private SSLSocket socket;

        public RequestHandler(SSLSocket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                System.out.println("Connect...");
                int data;
                while ((data = socket.getInputStream().read()) != -1) {
                    if ((data >= 97) && (data <= 122)) {
                        data -= 32;
                    } else if ((data >= 65) && (data <= 90)) {
                        data += 32;
                    }
                    socket.getOutputStream().write(data);
                    if (socket.getInputStream().available() == 0) {
                        socket.getOutputStream().flush();
                    }
                }
                socket.getOutputStream().flush();
                socket.close();
                System.out.println("Disconnect...");
            } catch (Exception e) {
                System.out.println("HANDLER: " + e);
            }
        }
    }
}
