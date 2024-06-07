import javax.net.ssl.*;
import java.io.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

public class TestClient {
    public static void main(String[] args) {
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
                SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket("localhost", 4999);
                String[] supportedCipherSuites = socket.getSupportedCipherSuites();
                socket.setEnabledCipherSuites(supportedCipherSuites);

                // Specify the same cipher suites as the server
                socket.setEnabledCipherSuites(socket.getSupportedCipherSuites());

                PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);
                writer.println("attack");

                socket.close();

                Thread.sleep(100); // 100 milliseconds delay between each request
            } catch (Exception ex) {
                System.out.println("Client exception: " + ex.getMessage());
                ex.printStackTrace();
            }
        }
    }
}