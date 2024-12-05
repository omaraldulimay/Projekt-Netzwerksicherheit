import java.util.Scanner;
import java.util.Set;
import java.util.Map;
import java.io.File;
import Logger;
import NetworkMonitor;
import MFAProvider;

public class Application {
    private static final Logger logger = new Logger();

    public static void main(String[] args) {
        NetworkMonitor networkMonitor = new NetworkMonitor();
        MFAProvider mfaProvider = new MFAProvider();
        Scanner scanner = new Scanner(System.in);

        // Überprüfen Sie das Vorhandensein des Logs-Verzeichnisses und erstellen Sie es, falls es nicht existiert
        File logsDir = new File("logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }

        // Generieren Sie einen dynamischen Verifizierungscode
        String dynamicVerificationCode = generateDynamicVerificationCode();
        mfaProvider.sendVerificationCode("admin", dynamicVerificationCode);

        // Zeigen Sie den generierten Verifizierungscode dem Benutzer an
        System.out.println("Generierter Verifizierungscode: " + dynamicVerificationCode);

        // Protokollieren Sie den generierten Verifizierungscode
        logger.logEvent("N/A", "Verifizierungscode", "Generierter Verifizierungscode: " + dynamicVerificationCode);

        System.out.print("Verifizierungscode eingeben: ");
        String enteredCode = scanner.nextLine();

        if (mfaProvider.verifyCode(enteredCode)) {
            networkMonitor.login("admin", "password", enteredCode);
            logger.logEvent("N/A", "Login-Versuch", "Login-Versuch für Benutzer: admin");

            // Demonstrieren Sie die Erstellung von Netzwerksegmenten und den eingeschränkten Zugriff zwischen ihnen
            networkMonitor.defineSegment("Segment1");
            networkMonitor.defineSegment("Segment2");
            networkMonitor.assignDeviceToSegment("Segment1", "192.168.1.1");
            networkMonitor.assignDeviceToSegment("Segment2", "192.168.2.1");
            networkMonitor.restrictAccessBetweenSegments("Segment1", "Segment2");

            // Autorisierungsüberprüfung
            if (networkMonitor.isUserAuthorized("admin", "ACCESS_NETWORK")) {
                System.out.println("Benutzer ist berechtigt, auf das Netzwerk zuzugreifen.");
                logger.logEvent("N/A", "Autorisierung", "Benutzer ist berechtigt, auf das Netzwerk zuzugreifen.");
            } else {
                System.out.println("Benutzer ist nicht berechtigt, auf das Netzwerk zuzugreifen.");
                logger.logEvent("N/A", "Autorisierung", "Benutzer ist nicht berechtigt, auf das Netzwerk zuzugreifen.");
            }

            // Daten verschlüsseln
            byte[] data = "Sensible Daten".getBytes();
            byte[] encryptedData = networkMonitor.encryptData(data);
            System.out.println("Daten verschlüsselt: " + new String(encryptedData));

            // Protokollieren Sie den Zugriffsversuch
            networkMonitor.logAccessAttempt("admin", "Netzwerkressource", true);

            // Angriffssignaturen laden
            networkMonitor.loadSignatures();

            // Demonstrieren Sie die Erkennung von Port-Scans
            networkMonitor.detectPortScanning("192.168.1.1", 8080);

            // Demonstrieren Sie die Erkennung verdächtiger Inhalte
            networkMonitor.scanMessageForKeywords("attack", "192.168.1.1");

            // Demonstrieren Sie die signaturbasierte Angriffserkennung
            networkMonitor.detectSignatureBasedAttack("attack_signature", "192.168.1.1");

            // Demonstrieren Sie die Erkennung von DoS-Angriffen
            networkMonitor.detectDoSAttack("192.168.1.1");
        } else {
            System.out.println("Ungültiger Verifizierungscode.");
        }
    }

    private static String generateDynamicVerificationCode() {
        // Generieren Sie einen zufälligen 6-stelligen Verifizierungscode
        int code = (int) (Math.random() * 900000) + 100000;
        return String.valueOf(code);
    }
}
