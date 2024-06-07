public class Application {
    public static void main(String[] args) {
        NetworkMonitor networkMonitor = new NetworkMonitor();
        networkMonitor.login("admin", "password", "123456");
    }
}