import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.io.File;

public class Logger {
    private static final String LOG_FILE_PATH = "logs/network_events.log";
    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void logEvent(String ipAddress, String eventType, String message) {
        String timestamp = LocalDateTime.now().format(DATE_TIME_FORMATTER);
        String logMessage = String.format("%s - IP: %s - Event: %s - Message: %s", timestamp, ipAddress, eventType, message);

        // Überprüfen Sie das Vorhandensein des Logs-Verzeichnisses und erstellen Sie es, falls es nicht existiert
        File logsDir = new File("logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE_PATH, true))) {
            writer.write(logMessage);
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Fehler beim Schreiben in die Protokolldatei: " + e.getMessage());
            e.printStackTrace(); // Hinzugefügt ordnungsgemäße Ausnahmebehandlung
        }
    }

    public void logAccessAttempt(String username, String resource, boolean success) {
        String timestamp = LocalDateTime.now().format(DATE_TIME_FORMATTER);
        String logMessage = String.format("%s - Benutzer: %s - Ressource: %s - Erfolg: %s", timestamp, username, resource, success);

        // Überprüfen Sie das Vorhandensein des Logs-Verzeichnisses und erstellen Sie es, falls es nicht existiert
        File logsDir = new File("logs");
        if (!logsDir.exists()) {
            logsDir.mkdirs();
        }

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE_PATH, true))) {
            writer.write(logMessage);
            writer.newLine();
        } catch (IOException e) {
            System.err.println("Fehler beim Schreiben in die Protokolldatei: " + e.getMessage());
            e.printStackTrace(); // Hinzugefügt ordnungsgemäße Ausnahmebehandlung
        }
    }
}
