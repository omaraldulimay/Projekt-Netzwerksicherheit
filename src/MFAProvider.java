public class MFAProvider {
    private String storedCode; // This will store the dynamic verification code

    public void sendVerificationCode(String username, String verificationCode) {
        this.storedCode = verificationCode;
        // In a real-world application, you would integrate with an SMS or email service to send the verification code
        System.out.println("A verification code has been sent to the user: " + username);
    }

    public boolean verifyCode(String enteredCode) {
        // In a real-world application, you would check the code entered by the user against the code that was sent to them
        return storedCode.equals(enteredCode);
    }
}
