package encryption.utility;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.Signature;

public class gen6 {

    private static final String CHAR_POOL =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private static final int KEY_LENGTH = 32;
    private static final int GCM_TAG_LENGTH = 128;
    private static final int IV_LENGTH = 12;

    // Update these values
    private static final String KEYSTORE_FILE = "keystore.jks";
    private static final String KEYSTORE_PASSWORD = "sbieis2025";
    private static final String KEY_ALIAS = "eis2";
 // certificate path
    private static final String PUBLIC_CERT_FILE = "public.crt";

    /**
     * Generate 32 Character AES Key
     */
    public static String generateDynamicKey() {

        SecureRandom secureRandom = new SecureRandom();

        StringBuilder key =
                new StringBuilder(KEY_LENGTH);

        for (int i = 0; i < KEY_LENGTH; i++) {

            key.append(
                    CHAR_POOL.charAt(
                            secureRandom.nextInt(
                                    CHAR_POOL.length()
                            )
                    )
            );
        }

        return key.toString();
    }

    /**
     * AES GCM Encrypt
     */
    public static String encryptJsonRequest(
            String jsonPayload,
            String secretKey)
            throws Exception {

        if (secretKey == null
                || secretKey.length() != 32) {

            throw new IllegalArgumentException(
                    "Secret key must be exactly 32 characters."
            );
        }

        byte[] keyBytes =
                secretKey.getBytes(
                        StandardCharsets.UTF_8);

        SecretKeySpec secretKeySpec =
                new SecretKeySpec(
                        keyBytes,
                        "AES");

        byte[] iv =
                new byte[IV_LENGTH];

        System.arraycopy(
                keyBytes,
                0,
                iv,
                0,
                IV_LENGTH);

        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv);

        Cipher cipher =
                Cipher.getInstance(
                        "AES/GCM/NoPadding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKeySpec,
                gcmSpec);

        byte[] encryptedBytes =
                cipher.doFinal(
                        jsonPayload.getBytes(
                                StandardCharsets.UTF_8));

        return Base64.getEncoder()
                .encodeToString(
                        encryptedBytes);
    }

    /**
     * AES GCM Decrypt
     */
    public static String decryptJsonRequest(
            String encryptedPayload,
            String secretKey)
            throws Exception {

        byte[] keyBytes =
                secretKey.getBytes(
                        StandardCharsets.UTF_8);

        SecretKeySpec secretKeySpec =
                new SecretKeySpec(
                        keyBytes,
                        "AES");

        byte[] iv =
                new byte[IV_LENGTH];

        System.arraycopy(
                keyBytes,
                0,
                iv,
                0,
                IV_LENGTH);

        GCMParameterSpec gcmSpec =
                new GCMParameterSpec(
                        GCM_TAG_LENGTH,
                        iv);

        Cipher cipher =
                Cipher.getInstance(
                        "AES/GCM/NoPadding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                secretKeySpec,
                gcmSpec);

        byte[] decryptedBytes =
                cipher.doFinal(
                        Base64.getDecoder()
                                .decode(
                                        encryptedPayload));

        return new String(
                decryptedBytes,
                StandardCharsets.UTF_8);
    }

    /**
     * Load Public Key from Keystore
     */
    private static PublicKey loadPublicKey()
            throws Exception {

        try (InputStream is =
                     gen6.class.getClassLoader()
                             .getResourceAsStream(
                                     KEYSTORE_FILE)) {

            if (is == null) {

                throw new RuntimeException(
                        "Cannot find "
                                + KEYSTORE_FILE);
            }

            KeyStore keyStore =
                    KeyStore.getInstance(
                            "PKCS12");

            keyStore.load(
                    is,
                    KEYSTORE_PASSWORD.toCharArray());

            Certificate certificate =
                    keyStore.getCertificate(
                            KEY_ALIAS);

            if (certificate == null) {

                throw new RuntimeException(
                        "Certificate not found for alias: "
                                + KEY_ALIAS);
            }

            return certificate.getPublicKey();
        }
    }

    /**
     * Load Private Key from Keystore
     */
    private static PrivateKey loadPrivateKey()
            throws Exception {

        try (InputStream is =
                     gen6.class.getClassLoader()
                             .getResourceAsStream(
                                     KEYSTORE_FILE)) {

            if (is == null) {

                throw new RuntimeException(
                        "Cannot find "
                                + KEYSTORE_FILE);
            }

            KeyStore keyStore =
                    KeyStore.getInstance(
                            "PKCS12");

            keyStore.load(
                    is,
                    KEYSTORE_PASSWORD.toCharArray());

            PrivateKey privateKey =
                    (PrivateKey) keyStore.getKey(
                            KEY_ALIAS,
                            KEYSTORE_PASSWORD.toCharArray());

            if (privateKey == null) {

                throw new RuntimeException(
                        "Private key not found for alias: "
                                + KEY_ALIAS);
            }

            return privateKey;
        }
    }

    /**
     * Encrypt AES Key using RSA OAEP
     */
    public static String encryptAESKey(
            String aesKey)
            throws Exception {

        PublicKey publicKey =
                loadPublicKey();

        Cipher cipher =
                Cipher.getInstance(
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                publicKey);

        byte[] encryptedKey =
                cipher.doFinal(
                        aesKey.getBytes(
                                StandardCharsets.UTF_8));

        return Base64.getEncoder()
                .encodeToString(
                        encryptedKey);
    }

    /**
     * Decrypt AES Key using RSA OAEP
     */
    public static String decryptAESKey(
            String encryptedAESKey)
            throws Exception {

        PrivateKey privateKey =
                loadPrivateKey();

        Cipher cipher =
                Cipher.getInstance(
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                privateKey);

        byte[] decryptedBytes =
                cipher.doFinal(
                        Base64.getDecoder()
                                .decode(
                                        encryptedAESKey));

        return new String(
                decryptedBytes,
                StandardCharsets.UTF_8);
    }
    /**
     * Load Public Key from X.509 Certificate (.crt)
     */
    private static PublicKey loadPublicKeyFromCrt() throws Exception {
        
        try (InputStream is = 
                     gen6.class.getClassLoader()
                             .getResourceAsStream(PUBLIC_CERT_FILE)) {
            
            if (is == null) {
                throw new RuntimeException("Cannot find" + PUBLIC_CERT_FILE	);
            }
            
            CertificateFactory fact = 
                    CertificateFactory.getInstance("X.509");
            
            X509Certificate cer = 
                    (X509Certificate) fact.generateCertificate(is);
            return cer.getPublicKey();
        }
    }
    /**
     * Generate Digital Signature using SHA-256 and RSA
     */
    public static String generateDigitalSignature(String payload) throws Exception {
        
        // Signatures must be generated with the PRIVATE key
        PrivateKey privateKey = loadPrivateKey();
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        
        signature.update(payload.getBytes(StandardCharsets.UTF_8));
        
        byte[] signedBytes = signature.sign();
        
        return Base64.getEncoder().encodeToString(signedBytes);
    }
    /**
     * Verify Digital Signature using X.509 Certificate Public Key
     */
    public static boolean verifyDigitalSignature(
            String payload, 
            String signatureString) throws Exception {
        
        // Signatures are verified with the PUBLIC key from the .crt
        PublicKey publicKey = loadPublicKeyFromCrt();
        
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        
        signature.update(payload.getBytes(StandardCharsets.UTF_8));
        
        byte[] signatureBytes = Base64.getDecoder().decode(signatureString);
        
        return signature.verify(signatureBytes);
    }

    public static void main(String[] args) {

        try {

            String secretKey =
                    generateDynamicKey();

            String jsonPayload =
                    "{"
                            + "\"customerId\":\"12345\","
                            + "\"name\":\"John Doe\","
                            + "\"amount\":5000,"
                            + "\"currency\":\"INR\""
                            + "}";

            String encryptedPayload =
                    encryptJsonRequest(
                            jsonPayload,
                            secretKey);

            String decryptedPayload =
                    decryptJsonRequest(
                            encryptedPayload,
                            secretKey);

            String encryptedAESKey =
                    encryptAESKey(
                            secretKey);

            String decryptedAESKey =
                    decryptAESKey(
                            encryptedAESKey);

            System.out.println(
                    "Original AES Key:\n"
                            + secretKey);

            System.out.println(
                    "\nEncrypted AES Key:\n"
                            + encryptedAESKey);

            System.out.println(
                    "\nDecrypted AES Key:\n"
                            + decryptedAESKey);

            System.out.println(
                    "\nEncrypted Payload:\n"
                            + encryptedPayload);

            System.out.println(
                    "\nDecrypted Payload:\n"
                            + decryptedPayload);
         // --- Digital Signature Testing ---
            String digitalSignature = generateDigitalSignature(jsonPayload);
            
            boolean isSignatureValid = verifyDigitalSignature(jsonPayload, digitalSignature);
            
            System.out.println("\nGenerated Digital Signature:\n" + digitalSignature);
            System.out.println("\nIs Signature Valid? " + isSignatureValid);

        } catch (Exception e) {

            e.printStackTrace();
        }
    }
}