import java.util.Scanner;

public class Application {
    private static final Logger logger = new Logger();

    public static void main(String[] args) {
        NetworkMonitor networkMonitor = new NetworkMonitor();
        Scanner scanner = new Scanner(System.in);

        // Generate a dynamic verification code and send it to the user
        String verificationCode = networkMonitor.generateVerificationCode("admin");

        System.out.print("Enter verification code: ");
        String enteredCode = scanner.nextLine();

        networkMonitor.login("admin", "password", enteredCode);
        logger.logEvent("N/A", "Login Attempt", "Login attempt for user: admin");

        // Demonstrate the creation of network segments and restricted access between them
        networkMonitor.defineSegment("Segment1");
        networkMonitor.defineSegment("Segment2");
        networkMonitor.assignDeviceToSegment("Segment1", "192.168.1.1");
        networkMonitor.assignDeviceToSegment("Segment2", "192.168.2.1");
        networkMonitor.restrictAccessBetweenSegments("Segment1", "Segment2");

        // Authorization check
        if (networkMonitor.isUserAuthorized("admin", "ACCESS_NETWORK")) {
            System.out.println("User is authorized to access the network.");
            logger.logEvent("N/A", "Authorization", "User is authorized to access the network.");
        } else {
            System.out.println("User is not authorized to access the network.");
            logger.logEvent("N/A", "Authorization", "User is not authorized to access the network.");
        }

        // Encrypt data
        byte[] data = "Sensitive data".getBytes();
        byte[] encryptedData = networkMonitor.encryptData(data);
        System.out.println("Data encrypted: " + new String(encryptedData));

        // Log access attempt
        networkMonitor.logAccessAttempt("admin", "Network Resource", true);
    }
}
