# ProjektBericht-Netzwerksicherheit

## Zusammenfassung des Projekts

Dieses Projekt implementiert verschiedene Funktionen zur Netzwerksicherheit, einschließlich der Erstellung von Netzwerksegmenten, der Beschränkung des Zugriffs, der Autorisierungsüberprüfung, der Datenverschlüsselung und der Protokollierung von Zugriffsversuchen. Es umfasst auch die Erkennung von Port-Scans, die Überprüfung auf verdächtige Inhalte, die signaturbasierte Angriffserkennung und die Erkennung von DoS-Angriffen.

## Implementierte Funktionen

- `src/Application.java`: Demonstriert die Erstellung von Netzwerksegmenten, die Beschränkung des Zugriffs, Autorisierungsüberprüfungen, Datenverschlüsselung und die Protokollierung von Zugriffsversuchen.
- `src/Logger.java`: Implementiert die Protokollierung von Netzwerkereignissen und Zugriffsversuchen.
- `src/MFAProvider.java`: Handhabt die Multi-Faktor-Authentifizierung durch das Senden und Überprüfen von Verifizierungscodes.
- `src/NetworkMonitor.java`: Beinhaltet Funktionen für Login, Port-Scan-Erkennung, Überprüfung auf verdächtige Inhalte, signaturbasierte Angriffserkennung, DoS-Angriffserkennung, Segmentverwaltung und Verschlüsselung.
- `src/TestClient.java`: Simuliert Client-Verbindungen und testet einige Funktionen wie die Protokollierung von Zugriffsversuchen und die Datenverschlüsselung.

## Schritt-für-Schritt-Plan zum Testen der Funktionen

1. **Netzwerksegmente erstellen und Zugriff beschränken**:
   - Öffnen Sie die Datei `src/Application.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die Netzwerksegmente erstellt und der Zugriff zwischen ihnen beschränkt wurde.

2. **Autorisierungsüberprüfung**:
   - Öffnen Sie die Datei `src/Application.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die Autorisierungsüberprüfung korrekt durchgeführt wurde.

3. **Datenverschlüsselung**:
   - Öffnen Sie die Datei `src/Application.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die Daten korrekt verschlüsselt wurden.

4. **Protokollierung von Zugriffsversuchen**:
   - Öffnen Sie die Datei `src/Application.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/Application.java` aus.
   - Überprüfen Sie die Datei `logs/network_events.log`, um sicherzustellen, dass die Zugriffsversuche korrekt protokolliert wurden.

5. **Port-Scan-Erkennung**:
   - Öffnen Sie die Datei `src/NetworkMonitor.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Simulieren Sie Port-Scans von verschiedenen IP-Adressen, indem Sie mehrere Verbindungen zu verschiedenen Ports auf dem Server herstellen.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die Port-Scans erkannt wurden.

6. **Überprüfung auf verdächtige Inhalte**:
   - Öffnen Sie die Datei `src/NetworkMonitor.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Senden Sie Nachrichten mit verdächtigen Inhalten (z.B. "attack", "hack", "malware") an den Server.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die verdächtigen Inhalte erkannt wurden.

7. **Signaturbasierte Angriffserkennung**:
   - Öffnen Sie die Datei `src/NetworkMonitor.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Senden Sie Nachrichten, die Angriffssignaturen enthalten (z.B. Inhalte aus der Datei `src/attack_signatures.txt`), an den Server.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die signaturbasierten Angriffe erkannt wurden.

8. **DoS-Angriffserkennung**:
   - Öffnen Sie die Datei `src/NetworkMonitor.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/NetworkMonitor.java` aus.
   - Simulieren Sie DoS-Angriffe, indem Sie eine große Anzahl von Anfragen von verschiedenen IP-Adressen an den Server senden.
   - Überprüfen Sie die Konsolenausgabe sowie die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die DoS-Angriffe erkannt wurden.

9. **Testen der Client-Verbindungen**:
   - Öffnen Sie die Datei `src/TestClient.java` in Ihrer IDE oder Ihrem Texteditor.
   - Führen Sie die Datei `src/TestClient.java` aus.
   - Überprüfen Sie die Konsolenausgabe und die Protokolldatei `logs/network_events.log`, um sicherzustellen, dass die Client-Verbindungen korrekt simuliert und die Funktionen wie die Protokollierung von Zugriffsversuchen und die Datenverschlüsselung getestet wurden.

10. **Multi-Faktor-Authentifizierung (MFA) testen**:
    - Öffnen Sie die Datei `src/Application.java` in Ihrer IDE oder Ihrem Texteditor.
    - Führen Sie die Datei `src/Application.java` aus.
    - Geben Sie den Verifizierungscode "123456" ein, wenn Sie dazu aufgefordert werden.
    - Überprüfen Sie die Konsolenausgabe, um sicherzustellen, dass die MFA korrekt funktioniert und der Benutzer erfolgreich authentifiziert wird.

11. **Erstellen des Logs-Verzeichnisses**:
    - Stellen Sie sicher, dass das Verzeichnis `logs` im Projektverzeichnis vorhanden ist.
    - Wenn das Verzeichnis nicht vorhanden ist, erstellen Sie es manuell oder führen Sie die Datei `src/Application.java` aus, um das Verzeichnis automatisch zu erstellen.
