public class MFAProvider {
    private String storedCode; // Dies wird den dynamischen Verifizierungscode speichern

    public void sendVerificationCode(String username, String verificationCode) {
        this.storedCode = verificationCode;
        // In einer realen Anwendung würden Sie einen SMS- oder E-Mail-Dienst integrieren, um den Verifizierungscode zu senden
        System.out.println("Ein Verifizierungscode wurde an den Benutzer gesendet: " + username);
        System.out.println("Generierter Verifizierungscode: " + verificationCode);
    }

    public boolean verifyCode(String enteredCode) {
        // In einer realen Anwendung würden Sie den vom Benutzer eingegebenen Code mit dem gesendeten Code abgleichen
        return storedCode.equals(enteredCode);
    }
}
