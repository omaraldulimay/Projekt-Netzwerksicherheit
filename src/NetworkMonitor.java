
import java.io.*;
import java.util.*;
import javax.net.ssl.*;

public class NetworkMonitor {
    private static final int MAX_CONNECTIONS_PER_IP = 50;
    private static final int MAX_REQUESTS_PER_MINUTE = 1000;
    private static final List<String> SUSPICIOUS_CONTENT_KEYWORDS = Arrays.asList("attack", "hack", "malware");

    private static final Map<String, Integer> connectionCounts = new HashMap<>();
    private static final Map<String, LinkedList<Long>> requestTimestamps = new HashMap<>();
    private static final Map<String, String> previousIPs = new HashMap<>();
    private static final Map<String, Set<Integer>> connectionPorts = new HashMap<>();
    private static final int MAX_SIMILAR_REQUESTS = 100;
    private static final Map<String, LinkedList<String>> recentRequests = new HashMap<>();
    private static final Set<String> blockedIPs = new HashSet<>();

    private final MFAProvider mfaProvider = new MFAProvider();

    public void login(String username, String password, String verificationCode) {
        if (isUsernameAndPasswordValid(username, password)) {
            if (mfaProvider.verifyCode(verificationCode)) {
                System.out.println("Login successful for user: " + username);
            } else {
                System.out.println("Invalid verification code for user: " + username);
            }
        } else {
            System.out.println("Invalid username or password for user: " + username);
        }
    }

    private boolean isUsernameAndPasswordValid(String username, String password) {
        // In a real-world application, you would check the username and password against your user database
        return "admin".equals(username) && "password".equals(password);
    }



    public static void main(String[] args) {
        boolean running = true;
        SSLServerSocket serverSocket;


            try {
                SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
                serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(4999);
                String[] supportedCipherSuites = serverSocket.getSupportedCipherSuites();
                serverSocket.setEnabledCipherSuites(supportedCipherSuites);
                serverSocket.setEnabledProtocols(new String[] {"TLSv1.2"}); // Specify the SSL/TLS protocol
                serverSocket.setEnabledCipherSuites(serverSocket.getSupportedCipherSuites()); // Enable all supported cipher suites
                serverSocket.setNeedClientAuth(false); // Optional: erfordert eine Authentifizierung des Clients

                System.out.println("Server hört auf Port 4999");
            } catch (IOException e) {
                System.out.println("Fehler beim Erstellen des SSL Server Sockets: " + e.getMessage());
                return;
            }
            while (running) {
                try {
                    SSLSocket socket = (SSLSocket) serverSocket.accept();
                    String clientIP = socket.getInetAddress().getHostAddress();
                    int clientPort = socket.getPort();

                // Überprüft ob, die IP-Adresse des Clients geändert wurde, was auf IP-Spoofing hinweisen könnte
                if (previousIPs.containsKey(clientIP) && !previousIPs.get(clientIP).equals(clientIP)) {
                    System.out.println("Möglicher IP-Spoofing-Angriff von IP erkannt: " + clientIP);
                }
                previousIPs.put(clientIP, clientIP);

                // Aktualisiert die Verbindungsanzahl für diese IP
                connectionCounts.put(clientIP, connectionCounts.getOrDefault(clientIP, 0) + 1);

                // Wenn die Verbindungsanzahl für diese IP das Limit überschreitet, wird eine Warnung ausgegeben
                if (connectionCounts.get(clientIP) > MAX_CONNECTIONS_PER_IP) {
                    System.out.println("Möglicher Port-Scan von IP erkannt: " + clientIP);
                }

                // Aktualisiert die Ports, zu denen diese IP Verbindungen herstellt
                if (!connectionPorts.containsKey(clientIP)) {
                    connectionPorts.put(clientIP, new HashSet<>());
                }
                connectionPorts.get(clientIP).add(clientPort);

                // Wenn die Anzahl der Ports, zu denen diese IP Verbindungen herstellt, das Limit überschreitet, wird eine Warnung ausgegeben
                if (connectionPorts.get(clientIP).size() > MAX_CONNECTIONS_PER_IP) {
                    System.out.println("Möglicher Port-Scan von IP erkannt: " + clientIP);
                }

                // Aktualisiert die Zeitstempel der Anfragen für diese IP
                if (!requestTimestamps.containsKey(clientIP)) {
                    requestTimestamps.put(clientIP, new LinkedList<>());
                }
                requestTimestamps.get(clientIP).add(System.currentTimeMillis());

                // Entfernt die Zeitstempel, die älter als eine Minute sind
                LinkedList<Long> timestamps = requestTimestamps.get(clientIP);
                if (timestamps != null && !timestamps.isEmpty() && timestamps.peek() < System.currentTimeMillis() - 60000) {
                    timestamps.remove();
                }

                // Wenn die Anzahl der Anfragen pro Minute für diese IP das Limit überschreitet, wird eine Warnung ausgegeben
                if (requestTimestamps.get(clientIP).size() > MAX_REQUESTS_PER_MINUTE) {
                    System.out.println("Möglicher DoS-Angriff von IP erkannt: " + clientIP);
                }

                System.out.println("Neuer Client verbunden");

                InputStream inputStream = socket.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Empfangen: " + line);

                    // Überprüft, ob der Inhalt der Nachricht verdächtige Schlüsselwörter enthält
                    for (String keyword : SUSPICIOUS_CONTENT_KEYWORDS) {
                        if (line.toLowerCase().contains(keyword)) {
                            System.out.println("Verdächtiger Paketinhalt von IP erkannt: " + clientIP);
                            blockedIPs.add(clientIP); // Blockieren Sie die IP-Adresse des Angreifers
                            break;
                        }
                    }

                    // Überprüft, ob die IP-Adresse des Clients blockiert ist
                    if (blockedIPs.contains(clientIP)) {
                        System.out.println("Blockierte IP versucht, eine Verbindung herzustellen: " + clientIP);
                        socket.close();
                        break;
                    }

                    // Überprüft, ob die Länge der Nachricht einen bestimmten Schwellenwert überschreitet
                    if (line.length() > 1000) {
                        System.out.println("Verdächtiger Paketinhalt von IP erkannt (Nachricht zu lang): " + clientIP);
                    }

                    // Überprüft, ob die Nachricht Sonderzeichen enthält
                    if (line.matches(".*[^a-zA-Z0-9 ].*")) {
                        System.out.println("Verdächtiger Paketinhalt von IP erkannt (Sonderzeichen in Nachricht): " + clientIP);
                    }

                    // Aktualisiert die letzten Anfragen für diese IP
                    if (!recentRequests.containsKey(clientIP)) {
                        recentRequests.put(clientIP, new LinkedList<>());
                    }
                    recentRequests.get(clientIP).add(line);



                    // Entfernt die alten Anfragen, wenn die Liste zu groß wird
                    if (recentRequests.get(clientIP).size() > MAX_SIMILAR_REQUESTS) {
                        recentRequests.get(clientIP).removeFirst();
                    }


                    // Überprüft, ob alle Anfragen ähnlich sind
                    boolean allRequestsSimilar = true;
                    String firstRequest = recentRequests.get(clientIP).getFirst();
                    for (String request : recentRequests.get(clientIP)) {
                        if (!request.equals(firstRequest)) {
                            allRequestsSimilar = false;
                            break;
                        }
                    }

                    // Wenn alle Anfragen ähnlich sind, wird eine Warnung ausgegeben
                    if (allRequestsSimilar) {
                        System.out.println("Möglicher DoS-Angriff von IP erkannt: " + clientIP);
                    }
                }



                socket.close();
            } catch (IOException ex) {
                System.out.println("Server-Ausnahme: " + ex.getMessage());
                ex.printStackTrace();
                running = false; // Stoppen Sie den Server, wenn eine Ausnahme auftritt
            }
        }
    }
}