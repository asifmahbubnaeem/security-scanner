// InsecureCrypto.java

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class InsecureCrypto {

    // Hardcoded AES key, 16 bytes
    private static final String AES_KEY = "0123456789ABCDEF";

    public static String encrypt(String plaintext) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(AES_KEY.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB mode is insecure
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] enc = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(enc);
    }

    public static void main(String[] args) throws Exception {
        String secret = "my super secret data";
        String encrypted = encrypt(secret);
        System.out.println(encrypted);
    }
}

