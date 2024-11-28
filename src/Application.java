import java.util.Scanner;

public class Application {
    public static void main(String[] args) {
        NetworkMonitor networkMonitor = new NetworkMonitor();
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter verification code: ");
        String verificationCode = scanner.nextLine();

        networkMonitor.login("admin", "password", verificationCode);
    }
}
