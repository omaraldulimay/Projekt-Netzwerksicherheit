import java.io.*;
import java.util.*;
import javax.net.ssl.*;
import java.net.BindException;

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

    private static final Logger logger = new Logger();

    private final Map<String, Set<String>> userRoles = new HashMap<>();
    private final Map<String, Set<String>> rolePermissions = new HashMap<>();

    public NetworkMonitor() {
        // Initialisieren Sie Rollen und Berechtigungen
        Set<String> adminRoles = new HashSet<>();
        adminRoles.add("ADMIN");
        userRoles.put("admin", adminRoles);

        Set<String> adminPermissions = new HashSet<>();
        adminPermissions.add("ACCESS_NETWORK");
        rolePermissions.put("ADMIN", adminPermissions);
    }

    public void login(String username, String password, String verificationCode) {
        mfaProvider.sendVerificationCode(username, verificationCode);
        if (isUsernameAndPasswordValid(username, password)) {
            if (mfaProvider.verifyCode(verificationCode)) {
                if (isUserAuthorized(username, "ACCESS_NETWORK")) {
                    System.out.println("Login erfolgreich für Benutzer: " + username);
                    logger.logEvent("N/A", "Login", "Login erfolgreich für Benutzer: " + username);
                } else {
                    System.out.println("Benutzer nicht autorisiert: " + username);
                    logger.logEvent("N/A", "Login", "Benutzer nicht autorisiert: " + username);
                }
            } else {
                System.out.println("Ungültiger Verifizierungscode für Benutzer: " + username);
                logger.logEvent("N/A", "Login", "Ungültiger Verifizierungscode für Benutzer: " + username);
            }
        } else {
            System.out.println("Ungültiger Benutzername oder Passwort für Benutzer: " + username);
            logger.logEvent("N/A", "Login", "Ungültiger Benutzername oder Passwort für Benutzer: " + username);
        }
    }

    private boolean isUsernameAndPasswordValid(String username, String password) {
        // In einer realen Anwendung würden Sie den Benutzernamen und das Passwort mit Ihrer Benutzerdatenbank abgleichen
        return "admin".equals(username) && "password".equals(password);
    }

    public static void detectPortScanning(String clientIP, int clientPort) {
        // Überprüfen Sie, ob sich die IP-Adresse des Clients geändert hat, was auf IP-Spoofing hinweisen könnte
        if (previousIPs.containsKey(clientIP) && !previousIPs.get(clientIP).equals(clientIP)) {
            System.out.println("Möglicher IP-Spoofing-Angriff von IP erkannt: " + clientIP);
            logger.logEvent(clientIP, "IP-Spoofing", "Möglicher IP-Spoofing-Angriff erkannt");
        }
        previousIPs.put(clientIP, clientIP);

        // Aktualisieren Sie die Verbindungsanzahl für diese IP
        connectionCounts.put(clientIP, connectionCounts.getOrDefault(clientIP, 0) + 1);

        // Wenn die Verbindungsanzahl für diese IP das Limit überschreitet, geben Sie eine Warnung aus
        if (connectionCounts.get(clientIP) > MAX_CONNECTIONS_PER_IP) {
            System.out.println("Möglicher Port-Scan von IP erkannt: " + clientIP);
            logger.logEvent(clientIP, "Port-Scan", "Möglicher Port-Scan erkannt");
            blockSuspiciousIP(clientIP);
        }

        // Aktualisieren Sie die Ports, mit denen diese IP verbunden ist
        if (!connectionPorts.containsKey(clientIP)) {
            connectionPorts.put(clientIP, new HashSet<>());
        }
        connectionPorts.get(clientIP).add(clientPort);

        // Wenn die Anzahl der Ports, mit denen diese IP verbunden ist, das Limit überschreitet, geben Sie eine Warnung aus
        if (connectionPorts.get(clientIP).size() > MAX_CONNECTIONS_PER_IP) {
            System.out.println("Möglicher Port-Scan von IP erkannt: " + clientIP);
            logger.logEvent(clientIP, "Port-Scan", "Möglicher Port-Scan erkannt");
            blockSuspiciousIP(clientIP);
        }
    }

    private static void blockSuspiciousIP(String clientIP) {
        blockedIPs.add(clientIP);
        System.out.println("IP-Adresse blockiert: " + clientIP);
        logger.logEvent(clientIP, "Blocked IP", "IP-Adresse blockiert");
    }

    public static void scanMessageForKeywords(String message, String clientIP) {
        for (String keyword : SUSPICIOUS_CONTENT_KEYWORDS) {
            if (message.toLowerCase().contains(keyword)) {
                System.out.println("Verdächtiger Paketinhalt von IP erkannt: " + clientIP);
                logger.logEvent(clientIP, "Suspicious Content", "Verdächtiger Paketinhalt erkannt: " + message);
                blockSuspiciousIP(clientIP);
                break;
            }
        }
    }

    public void loadSignatures() {
        String path = "src/attack_signatures.txt";
        File file = new File(path);
        if (!file.exists()) {
            System.out.println("Warnung: Datei mit Angriffssignaturen nicht gefunden: " + file.getPath());
            logger.logEvent("N/A", "Warnung", "Datei mit Angriffssignaturen nicht gefunden: " + file.getPath());
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                attackSignatures.add(line);
            }
        } catch (IOException e) {
            System.out.println("Fehler beim Laden der Signaturen: " + e.getMessage());
            logger.logEvent("N/A", "Fehler", "Fehler beim Laden der Signaturen: " + e.getMessage());
        }
    }

    public static void detectSignatureBasedAttack(String message, String clientIP) {
        for (String signature : attackSignatures) {
            if (message.contains(signature)) {
                System.out.println("Signaturbasierter Angriff von IP erkannt: " + clientIP);
                logger.logEvent(clientIP, "Signature-Based Attack", "Signaturbasierter Angriff erkannt");
                blockSuspiciousIP(clientIP);
                break;
            }
        }
    }

    public static void detectDoSAttack(String clientIP) {
        if (requestTimestamps.get(clientIP) == null) {
            requestTimestamps.put(clientIP, new LinkedList<>());
        }
        if (requestTimestamps.get(clientIP).size() > MAX_REQUESTS_PER_MINUTE) {
            System.out.println("Möglicher DoS-Angriff von IP erkannt: " + clientIP);
            logger.logEvent(clientIP, "DoS Attack", "Möglicher DoS-Angriff erkannt");
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
        System.out.println("Segment nicht gefunden: " + segmentName);
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
            System.out.println("Eines oder beide Segmente nicht gefunden: " + segmentName1 + ", " + segmentName2);
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
        String message = String.format("Benutzer: %s hat versucht, auf Ressource zuzugreifen: %s - Erfolg: %s", username, resource, success);
        logger.logEvent("N/A", "Access Attempt", message);
    }

    public void reviewPermissions() {
        // In einer realen Anwendung würden Sie regelmäßig Berechtigungen, Richtlinien und Sicherheitsmaßnahmen überprüfen und aktualisieren
        System.out.println("Überprüfung und Aktualisierung von Berechtigungen, Richtlinien und Sicherheitsmaßnahmen...");
        logger.logEvent("N/A", "Review", "Überprüfung und Aktualisierung von Berechtigungen, Richtlinien und Sicherheitsmaßnahmen");
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
        // In einer realen Anwendung würden Sie TLS/SSL verwenden, um Daten während der Übertragung und im Ruhezustand zu verschlüsseln
        System.out.println("Daten werden verschlüsselt...");
        logger.logEvent("N/A", "Encryption", "Daten werden verschlüsselt");
        return data; // Platzhalter für die eigentliche Verschlüsselungslogik
    }

    public static void main(String[] args) {
        boolean running = true;
        SSLServerSocket serverSocket = null;

        try {
            SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
            serverSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(4999);
            String[] supportedCipherSuites = serverSocket.getSupportedCipherSuites();
            serverSocket.setEnabledCipherSuites(supportedCipherSuites);
            serverSocket.setEnabledProtocols(new String[] {"TLSv1.2"}); // Geben Sie das SSL/TLS-Protokoll an
            serverSocket.setEnabledCipherSuites(serverSocket.getSupportedCipherSuites()); // Aktivieren Sie alle unterstützten Cipher-Suites
            serverSocket.setNeedClientAuth(false); // Optional: erfordert eine Authentifizierung des Clients

            System.out.println("Server hört auf Port 4999");

            NetworkMonitor networkMonitor = new NetworkMonitor();
            networkMonitor.loadSignatures();

            // Demonstrieren Sie die Erstellung von Netzwerksegmenten und den eingeschränkten Zugriff zwischen ihnen
            networkMonitor.defineSegment("Segment1");
            networkMonitor.defineSegment("Segment2");
            networkMonitor.assignDeviceToSegment("Segment1", "192.168.1.1");
            networkMonitor.assignDeviceToSegment("Segment2", "192.168.2.1");
            networkMonitor.restrictAccessBetweenSegments("Segment1", "Segment2");

        } catch (BindException e) {
            System.out.println("Port 4999 ist bereits in Verwendung. Bitte schließen Sie die Anwendung, die diesen Port verwendet, oder wählen Sie einen anderen Port.");
            return;
        } catch (IOException e) {
            System.out.println("Fehler beim Erstellen des SSL-Server-Sockets: " + e.getMessage());
            return;
        }

        while (running) {
            try {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                String clientIP = socket.getInetAddress().getHostAddress();
                int clientPort = socket.getPort();

                detectPortScanning(clientIP, clientPort);

                // Aktualisieren Sie die Zeitstempel der Anfragen für diese IP
                if (!requestTimestamps.containsKey(clientIP)) {
                    requestTimestamps.put(clientIP, new LinkedList<>());
                }
                requestTimestamps.get(clientIP).add(System.currentTimeMillis());

                // Entfernen Sie die Zeitstempel, die älter als eine Minute sind
                LinkedList<Long> timestamps = requestTimestamps.get(clientIP);
                if (timestamps != null && !timestamps.isEmpty() && timestamps.peek() < System.currentTimeMillis() - 60000) {
                    timestamps.remove();
                }

                // Wenn die Anzahl der Anfragen pro Minute für diese IP das Limit überschreitet, geben Sie eine Warnung aus
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

                    // Überprüfen Sie, ob die IP-Adresse des Clients blockiert ist
                    if (blockedIPs.contains(clientIP)) {
                        System.out.println("Blockierte IP versucht, eine Verbindung herzustellen: " + clientIP);
                        logger.logEvent(clientIP, "Blocked IP Attempt", "Blockierte IP versucht, eine Verbindung herzustellen");
                        socket.close();
                        break;
                    }

                    // Überprüfen Sie, ob die Länge der Nachricht einen bestimmten Schwellenwert überschreitet
                    if (line.length() > 1000) {
                        System.out.println("Verdächtiger Paketinhalt von IP erkannt (Nachricht zu lang): " + clientIP);
                        logger.logEvent(clientIP, "Suspicious Content", "Verdächtiger Paketinhalt erkannt (Nachricht zu lang)");
                    }

                    // Überprüfen Sie, ob die Nachricht Sonderzeichen enthält
                    if (line.matches(".*[^a-zA-Z0-9 ].*")) {
                        System.out.println("Verdächtiger Paketinhalt von IP erkannt (Sonderzeichen in Nachricht): " + clientIP);
                        logger.logEvent(clientIP, "Suspicious Content", "Verdächtiger Paketinhalt erkannt (Sonderzeichen in Nachricht)");
                    }

                    // Aktualisieren Sie die letzten Anfragen für diese IP
                    if (!recentRequests.containsKey(clientIP)) {
                        recentRequests.put(clientIP, new LinkedList<>());
                    }
                    recentRequests.get(clientIP).add(line);

                    // Entfernen Sie die alten Anfragen, wenn die Liste zu groß wird
                    if (recentRequests.get(clientIP).size() > MAX_SIMILAR_REQUESTS) {
                        recentRequests.get(clientIP).removeFirst();
                    }

                    // Überprüfen Sie, ob alle Anfragen ähnlich sind
                    boolean allRequestsSimilar = true;
                    String firstRequest = recentRequests.get(clientIP).getFirst();
                    for (String request : recentRequests.get(clientIP)) {
                        if (!request.equals(firstRequest)) {
                            allRequestsSimilar = false;
                            break;
                        }
                    }

                    // Wenn alle Anfragen ähnlich sind, geben Sie eine Warnung aus
                    if (allRequestsSimilar) {
                        System.out.println("Möglicher DoS-Angriff von IP erkannt: " + clientIP);
                        logger.logEvent(clientIP, "DoS Attack", "Möglicher DoS-Angriff erkannt");
                    }
                }

                socket.close();
            } catch (SSLHandshakeException ex) {
                System.out.println("SSLHandshakeException: " + ex.getMessage());
                logger.logEvent("N/A", "SSLHandshakeException", "SSLHandshakeException: " + ex.getMessage());
            } catch (IOException ex) {
                System.out.println("Server-Ausnahme: " + ex.getMessage());
                ex.printStackTrace();
                running = false; // Stoppen Sie den Server, wenn eine Ausnahme auftritt
            }
        }
    }
}
