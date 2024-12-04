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

        System.out.print("Serveradresse eingeben: ");
        String serverAddress = scanner.nextLine();

        System.out.print("Serverport eingeben: ");
        int serverPort = scanner.nextInt();
        scanner.nextLine(); // Zeilenumbruch konsumieren

        System.out.print("Nachricht zum Senden eingeben: ");
        String message = scanner.nextLine();

        System.out.println("Debug: Eingegebene Serveradresse: " + serverAddress);
        System.out.println("Debug: Eingegebener Serverport: " + serverPort);
        System.out.println("Debug: Nachricht zum Senden: " + message);

        try {
            // Erstellen Sie einen Trust-Manager, der Zertifikatsketten nicht validiert
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

            // Installieren Sie den all-vertrauenswürdigen Trust-Manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new SecureRandom());

            // Erstellen Sie eine SSLSocketFactory, die unseren all-vertrauenswürdigen Manager verwendet
            SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(serverAddress, serverPort);
            String[] supportedCipherSuites = socket.getSupportedCipherSuites();
            socket.setEnabledCipherSuites(supportedCipherSuites);

            // Geben Sie die gleichen Cipher-Suites wie der Server an
            socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
            writer.println(message);

            System.out.println("Debug: Nachricht an den Server gesendet: " + message);

            // Protokollieren Sie den Zugriffsversuch
            Logger logger = new Logger();
            logger.logAccessAttempt("testUser", "Netzwerkressource", true);

            // Daten verschlüsseln
            NetworkMonitor networkMonitor = new NetworkMonitor();
            byte[] data = "Sensible Daten".getBytes();
            byte[] encryptedData = networkMonitor.encryptData(data);
            System.out.println("Daten verschlüsselt: " + new String(encryptedData));

            // Port-Scans simulieren
            simulatePortScans(serverAddress, serverPort);

            socket.close();
        } catch (Exception ex) {
            System.out.println("Client-Ausnahme: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    private static void simulatePortScans(String serverAddress, int serverPort) {
        List<Integer> portsToScan = new ArrayList<>();
        for (int i = 1; i <= 1024; i++) {
            portsToScan.add(i);
        }

        for (int port : portsToScan) {
            try {
                SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(serverAddress, port);
                socket.close();
                System.out.println("Port " + port + " ist offen.");
            } catch (IOException e) {
                System.out.println("Port " + port + " ist geschlossen.");
            }
        }
    }
}
