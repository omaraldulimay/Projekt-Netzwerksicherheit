# ProjektBericht-Netzwerksicherheit

## Zusammenfassung des Projekts

Dieses Projekt implementiert verschiedene Funktionen zur Netzwerksicherheit, einschließlich der Erstellung von Netzwerksegmenten, der Beschränkung des Zugriffs, der Autorisierungsüberprüfung, der Datenverschlüsselung und der Protokollierung von Zugriffsversuchen. Es umfasst auch die Erkennung von Port-Scans, die Überprüfung auf verdächtige Inhalte, die signaturbasierte Angriffserkennung und die Erkennung von DoS-Angriffen.

## Implementierte Funktionen

- `src/Application.java`: Demonstriert die Erstellung von Netzwerksegmenten, die Beschränkung des Zugriffs, Autorisierungsüberprüfungen, Datenverschlüsselung und die Protokollierung von Zugriffsversuchen.
- `src/Logger.java`: Implementiert die Protokollierung von Netzwerkereignissen und Zugriffsversuchen.
- `src/MFAProvider.java`: Handhabt die Multi-Faktor-Authentifizierung durch das Senden und Überprüfen von Verifizierungscodes.
- `src/NetworkMonitor.java`: Beinhaltet Funktionen für Login, Port-Scan-Erkennung, Überprüfung auf verdächtige Inhalte, signaturbasierte Angriffserkennung, DoS-Angriffserkennung, Segmentverwaltung und Verschlüsselung.
- `src/TestClient.java`: Simuliert Client-Verbindungen und testet einige Funktionen wie die Protokollierung von Zugriffsversuchen und die Datenverschlüsselung.

## Kurzanleitung zum Testen der Funktionen

1. **Netzwerksegmente erstellen und Zugriff beschränken**:
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die Netzwerksegmente erstellt und der Zugriff zwischen ihnen beschränkt wurde.

2. **Autorisierungsüberprüfung**:
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die Autorisierungsüberprüfung korrekt durchgeführt wurde.

3. **Datenverschlüsselung**:
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die Daten korrekt verschlüsselt wurden.

4. **Protokollierung von Zugriffsversuchen**:
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Datei `logs/network_events.log`, um sicherzustellen, dass die Zugriffsversuche korrekt protokolliert wurden.

5. **Port-Scan-Erkennung**:
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Simulieren Sie Port-Scans von verschiedenen IP-Adressen, indem Sie mehrere Verbindungen zu verschiedenen Ports auf dem Server herstellen.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die Port-Scans erkannt wurden.

6. **Überprüfung auf verdächtige Inhalte**:
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Senden Sie Nachrichten mit verdächtigen Inhalten (z.B. "attack", "hack", "malware") an den Server.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die verdächtigen Inhalte erkannt wurden.

7. **Signaturbasierte Angriffserkennung**:
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Senden Sie Nachrichten, die Angriffssignaturen enthalten (z.B. Inhalte aus der Datei `src/attack_signatures.txt`), an den Server.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die signaturbasierten Angriffe erkannt wurden.

8. **DoS-Angriffserkennung**:
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Simulieren Sie DoS-Angriffe, indem Sie eine große Anzahl von Anfragen von verschiedenen IP-Adressen an den Server senden.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die DoS-Angriffe erkannt wurden.

9. **Testen der Client-Verbindungen**:
   - Führen Sie die Datei `src/TestClient.java` aus.
   - Überprüfen Sie die Konsolenausgabe und die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die Client-Verbindungen korrekt simuliert und die Funktionen wie die Protokollierung von Zugriffsversuchen und die Datenverschlüsselung getestet wurden.

10. **Multi-Faktor-Authentifizierung (MFA) testen**:
    - Führen Sie die Datei `src/Application.java` aus.
    - Geben Sie den dynamischen Verifizierungscode ein, der an den Benutzer "admin" gesendet wurde.
    - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die MFA korrekt funktioniert und der Benutzer erfolgreich authentifiziert wird.

## Java Extension für Visual Studio Code (VSC)

Um die Java-Dateien in Visual Studio Code (VSC) auszuführen und zu testen, benötigen Sie die Java Extension. Folgen Sie diesen Schritten, um die Java Extension in VSC zu installieren:

1. Öffnen Sie Visual Studio Code.
2. Klicken Sie auf das Erweiterungssymbol in der Seitenleiste oder drücken Sie `Ctrl+Shift+X`, um den Erweiterungsbereich zu öffnen.
3. Geben Sie "Java Extension Pack" in das Suchfeld ein.
4. Klicken Sie auf "Installieren" neben dem "Java Extension Pack" von Microsoft.
5. Nach der Installation der Erweiterung können Sie Ihre Java-Dateien in VSC ausführen und testen.
