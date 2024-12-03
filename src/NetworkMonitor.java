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
    private static final List<String> attackSignatures = new ArrayList<>();

    private final MFAProvider mfaProvider = new MFAProvider();

    private final List<NetworkSegment> networkSegments = new ArrayList<>();

    private final Logger logger = new Logger();

    private final Map<String, Set<String>> userRoles = new HashMap<>();
    private final Map<String, Set<String>> rolePermissions = new HashMap<>();

    public void login(String username, String password, String verificationCode) {
        if (isUsernameAndPasswordValid(username, password)) {
            if (mfaProvider.verifyCode(verificationCode)) {
                if (isUserAuthorized(username, "ACCESS_NETWORK")) {
                    System.out.println("Login successful for user: " + username);
                    logger.logEvent("N/A", "Login", "Login successful for user: " + username);
                } else {
                    System.out.println("User not authorized: " + username);
                    logger.logEvent("N/A", "Login", "User not authorized: " + username);
                }
            } else {
                System.out.println("Invalid verification code for user: " + username);
                logger.logEvent("N/A", "Login", "Invalid verification code for user: " + username);
            }
        } else {
            System.out.println("Invalid username or password for user: " + username);
            logger.logEvent("N/A", "Login", "Invalid username or password for user: " + username);
        }
    }

    private boolean isUsernameAndPasswordValid(String username, String password) {
        // In a real-world application, you would check the username and password against your user database
        return "admin".equals(username) && "password".equals(password);
    }

    public void detectPortScanning(String clientIP, int clientPort) {
        // Check if the client's IP address has changed, which could indicate IP spoofing
        if (previousIPs.containsKey(clientIP) && !previousIPs.get(clientIP).equals(clientIP)) {
            System.out.println("Possible IP spoofing attack detected from IP: " + clientIP);
            logger.logEvent(clientIP, "IP-Spoofing", "Possible IP spoofing attack detected");
        }
        previousIPs.put(clientIP, clientIP);

        // Update the connection count for this IP
        connectionCounts.put(clientIP, connectionCounts.getOrDefault(clientIP, 0) + 1);

        // If the connection count for this IP exceeds the limit, issue a warning
        if (connectionCounts.get(clientIP) > MAX_CONNECTIONS_PER_IP) {
            System.out.println("Possible port scan detected from IP: " + clientIP);
            logger.logEvent(clientIP, "Port-Scan", "Possible port scan detected");
            blockSuspiciousIP(clientIP);
        }

        // Update the ports this IP is connecting to
        if (!connectionPorts.containsKey(clientIP)) {
            connectionPorts.put(clientIP, new HashSet<>());
        }
        connectionPorts.get(clientIP).add(clientPort);

        // If the number of ports this IP is connecting to exceeds the limit, issue a warning
        if (connectionPorts.get(clientIP).size() > MAX_CONNECTIONS_PER_IP) {
            System.out.println("Possible port scan detected from IP: " + clientIP);
            logger.logEvent(clientIP, "Port-Scan", "Possible port scan detected");
            blockSuspiciousIP(clientIP);
        }
    }

    private void blockSuspiciousIP(String clientIP) {
        blockedIPs.add(clientIP);
        System.out.println("IP address blocked: " + clientIP);
        logger.logEvent(clientIP, "Blocked IP", "IP address blocked");
    }

    public void scanMessageForKeywords(String message, String clientIP) {
        for (String keyword : SUSPICIOUS_CONTENT_KEYWORDS) {
            if (message.toLowerCase().contains(keyword)) {
                System.out.println("Suspicious packet content detected from IP: " + clientIP);
                logger.logEvent(clientIP, "Suspicious Content", "Suspicious packet content detected");
                blockSuspiciousIP(clientIP);
                break;
            }
        }
    }

    public void loadSignatures() {
        try (BufferedReader br = new BufferedReader(new FileReader("src/attack_signatures.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                attackSignatures.add(line);
            }
        } catch (IOException e) {
            System.out.println("Error loading signatures: " + e.getMessage());
            logger.logEvent("N/A", "Error", "Error loading signatures: " + e.getMessage());
        }
    }

    public void detectSignatureBasedAttack(String message, String clientIP) {
        for (String signature : attackSignatures) {
            if (message.contains(signature)) {
                System.out.println("Signature-based attack detected from IP: " + clientIP);
                logger.logEvent(clientIP, "Signature-Based Attack", "Signature-based attack detected");
                blockSuspiciousIP(clientIP);
                break;
            }
        }
    }

    public void detectDoSAttack(String clientIP) {
        if (requestTimestamps.get(clientIP).size() > MAX_REQUESTS_PER_MINUTE) {
            System.out.println("Possible DoS attack detected from IP: " + clientIP);
            logger.logEvent(clientIP, "DoS Attack", "Possible DoS attack detected");
            blockSuspiciousIP(clientIP);
        }
    }

    private boolean isTLSEnabled(SSLSocket socket) {
        String[] enabledProtocols = socket.getEnabledProtocols();
        for (String protocol : enabledProtocols) {
            if (protocol.equals("TLSv1.2")) {
                return true;
            }
        }
        return false;
    }

    private boolean verifyMFA(String verificationCode) {
        return mfaProvider.verifyCode(verificationCode);
    }

    public void defineSegment(String segmentName) {
        networkSegments.add(new NetworkSegment(segmentName));
    }

    public void assignDeviceToSegment(String segmentName, String deviceIP) {
        for (NetworkSegment segment : networkSegments) {
            if (segment.getSegmentName().equals(segmentName)) {
                segment.addAllowedIP(deviceIP);
                return;
            }
        }
        System.out.println("Segment not found: " + segmentName);
    }

    public void restrictAccessBetweenSegments(String segmentName1, String segmentName2) {
        NetworkSegment segment1 = null;
        NetworkSegment segment2 = null;

        for (NetworkSegment segment : networkSegments) {
            if (segment.getSegmentName().equals(segmentName1)) {
                segment1 = segment;
            } else if (segment.getSegmentName().equals(segmentName2)) {
                segment2 = segment;
            }
        }

        if (segment1 == null || segment2 == null) {
            System.out.println("One or both segments not found: " + segmentName1 + ", " + segmentName2);
            return;
        }

        for (String ip : segment1.getAllowedIPs()) {
            if (segment2.isIPAllowed(ip)) {
                segment2.removeAllowedIP(ip);
            }
        }

        for (String ip : segment2.getAllowedIPs()) {
            if (segment1.isIPAllowed(ip)) {
                segment1.removeAllowedIP(ip);
            }
        }
    }

    public void logAccessAttempt(String username, String resource, boolean success) {
        String message = String.format("User: %s attempted to access resource: %s - Success: %s", username, resource, success);
        logger.logEvent("N/A", "Access Attempt", message);
    }

    public void reviewPermissions() {
        // In a real-world application, you would review and update permissions, policies, and security measures regularly
        System.out.println("Reviewing and updating permissions, policies, and security measures...");
        logger.logEvent("N/A", "Review", "Reviewing and updating permissions, policies, and security measures");
    }

    public boolean isUserAuthorized(String username, String permission) {
        Set<String> roles = userRoles.get(username);
        if (roles == null) {
            return false;
        }
        for (String role : roles) {
            Set<String> permissions = rolePermissions.get(role);
            if (permissions != null && permissions.contains(permission)) {
                return true;
            }
        }
        return false;
    }

    public byte[] encryptData(byte[] data) {
        // In a real-world application, you would use TLS/SSL to encrypt data during transmission and at rest
        System.out.println("Encrypting data...");
        logger.logEvent("N/A", "Encryption", "Encrypting data");
        return data; // Placeholder for actual encryption logic
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

            NetworkMonitor networkMonitor = new NetworkMonitor();
            networkMonitor.loadSignatures();

            // Demonstrate the creation of network segments and restricted access between them
            networkMonitor.defineSegment("Segment1");
            networkMonitor.defineSegment("Segment2");
            networkMonitor.assignDeviceToSegment("Segment1", "192.168.1.1");
            networkMonitor.assignDeviceToSegment("Segment2", "192.168.2.1");
            networkMonitor.restrictAccessBetweenSegments("Segment1", "Segment2");

        } catch (IOException e) {
            System.out.println("Fehler beim Erstellen des SSL Server Sockets: " + e.getMessage());
            return;
        }
        while (running) {
            try {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                String clientIP = socket.getInetAddress().getHostAddress();
                int clientPort = socket.getPort();

                detectPortScanning(clientIP, clientPort);

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
                    logger.logEvent(clientIP, "DoS Attack", "Möglicher DoS-Angriff erkannt");
                    blockSuspiciousIP(clientIP);
                }

                System.out.println("Neuer Client verbunden");
                logger.logEvent(clientIP, "Connection", "Neuer Client verbunden");

                InputStream inputStream = socket.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("Empfangen: " + line);
                    logger.logEvent(clientIP, "Message Received", "Empfangen: " + line);

                    scanMessageForKeywords(line, clientIP);
                    detectSignatureBasedAttack(line, clientIP);
                    detectDoSAttack(clientIP);

                    // Überprüft, ob die IP-Adresse des Clients blockiert ist
                    if (blockedIPs.contains(clientIP)) {
                        System.out.println("Blockierte IP versucht, eine Verbindung herzustellen: " + clientIP);
                        logger.logEvent(clientIP, "Blocked IP Attempt", "Blockierte IP versucht, eine Verbindung herzustellen");
                        socket.close();
                        break;
                    }

                    // Überprüft, ob die Länge der Nachricht einen bestimmten Schwellenwert überschreitet
                    if (line.length() > 1000) {
                        System.out.println("Verdächtiger Paketinhalt von IP erkannt (Nachricht zu lang): " + clientIP);
                        logger.logEvent(clientIP, "Suspicious Content", "Verdächtiger Paketinhalt erkannt (Nachricht zu lang)");
                    }

                    // Überprüft, ob die Nachricht Sonderzeichen enthält
                    if (line.matches(".*[^a-zA-Z0-9 ].*")) {
                        System.out.println("Verdächtiger Paketinhalt von IP erkannt (Sonderzeichen in Nachricht): " + clientIP);
                        logger.logEvent(clientIP, "Suspicious Content", "Verdächtiger Paketinhalt erkannt (Sonderzeichen in Nachricht)");
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
                        logger.logEvent(clientIP, "DoS Attack", "Möglicher DoS-Angriff erkannt");
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
