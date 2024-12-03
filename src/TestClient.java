import javax.net.ssl.*;
import java.io.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.List;
import java.util.ArrayList;

public class TestClient {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter server address: ");
        String serverAddress = scanner.nextLine();

        System.out.print("Enter server port: ");
        int serverPort = scanner.nextInt();
        scanner.nextLine(); // Consume newline

        System.out.print("Enter message to send: ");
        String message = scanner.nextLine();

        List<String> ipAddresses = new ArrayList<>();
        ipAddresses.add("192.168.1.1");
        ipAddresses.add("192.168.1.2");
        ipAddresses.add("192.168.1.3");

        List<Integer> ports = new ArrayList<>();
        ports.add(8080);
        ports.add(8081);
        ports.add(8082);

        for (String ipAddress : ipAddresses) {
            for (int port : ports) {
                for (int i = 0; i < 100; i++) {
                    try {
                        // Create a trust manager that does not validate certificate chains
                        TrustManager[] trustAllCerts = new TrustManager[] {
                            new X509TrustManager() {
                                public X509Certificate[] getAcceptedIssuers() {
                                    return new X509Certificate[0];
                                }
                                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                                }
                                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                                }
                            }
                        };

                        // Install the all-trusting trust manager
                        SSLContext sc = SSLContext.getInstance("SSL");
                        sc.init(null, trustAllCerts, new SecureRandom());

                        // Create an SSLSocketFactory that uses our all-trusting manager
                        SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
                        SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(ipAddress, port);
                        String[] supportedCipherSuites = socket.getSupportedCipherSuites();
                        socket.setEnabledCipherSuites(supportedCipherSuites);

                        // Specify the same cipher suites as the server
                        socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

                        PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
                        writer.println(message);

                        // Log access attempt
                        Logger logger = new Logger();
                        logger.logAccessAttempt("testUser", "Network Resource", true);

                        // Encrypt data
                        NetworkMonitor networkMonitor = new NetworkMonitor();
                        byte[] data = "Sensitive data".getBytes();
                        byte[] encryptedData = networkMonitor.encryptData(data);
                        System.out.println("Data encrypted: " + new String(encryptedData));

                        socket.close();

                        Thread.sleep(100); // 100 milliseconds delay between each request
                    } catch (Exception ex) {
                        System.out.println("Client exception: " + ex.getMessage());
                        ex.printStackTrace();
                    }
                }
            }
        }
    }
}
