package encryption.utility;

import java.io.FileInputStream;
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
    public static String encryptJsonRequest(String jsonPayload,String secretKey) throws Exception {
        if (secretKey == null
                || secretKey.length() != 32) {
            throw new IllegalArgumentException(
                    "Secret key must be exactly 32 characters."
            );
        }
        byte[] keyBytes =secretKey.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec secretKeySpec =new SecretKeySpec(keyBytes,"AES");
        byte[] iv =new byte[IV_LENGTH];
        System.arraycopy(keyBytes,0,iv,0,IV_LENGTH);
        GCMParameterSpec gcmSpec =new GCMParameterSpec(GCM_TAG_LENGTH,iv);
        Cipher cipher =Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKeySpec,
                gcmSpec);
        byte[] encryptedBytes =
                cipher.doFinal(
                        jsonPayload.getBytes(
                                StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
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
	public static String encryptAESKey(
	        String aesKey,
	        String keystoreFile,
	        String keystorePassword,
	        String keyAlias)
	        throws Exception {

	    PublicKey publicKey =
	            loadPublicKey(
	                    keystoreFile,
	                    keystorePassword,
	                    keyAlias);

	    Cipher cipher =
	            Cipher.getInstance(
	                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

	    cipher.init(
	            Cipher.ENCRYPT_MODE,
	            publicKey);

	    return Base64.getEncoder()
	            .encodeToString(
	                    cipher.doFinal(
	                            aesKey.getBytes(
	                                    StandardCharsets.UTF_8)));
	}
	public static String decryptAESKey(
	        String encryptedAESKey,
	        String keystoreFile,
	        String keystorePassword,
	        String keyAlias)
	        throws Exception {

	    PrivateKey privateKey =
	            loadPrivateKey(
	                    keystoreFile,
	                    keystorePassword,
	                    keyAlias);

	    Cipher cipher =
	            Cipher.getInstance(
	                    "RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

	    cipher.init(
	            Cipher.DECRYPT_MODE,
	            privateKey);

	    return new String(
	            cipher.doFinal(
	                    Base64.getDecoder()
	                            .decode(encryptedAESKey)),
	            StandardCharsets.UTF_8);
	}
	private static PublicKey loadPublicKey(
	        String keystoreFile,
	        String keystorePassword,
	        String keyAlias)
	        throws Exception {

	    try (InputStream is =
	                 gen6.class.getClassLoader()
	                         .getResourceAsStream(
	                                 keystoreFile)) {

	        KeyStore keyStore =
	                KeyStore.getInstance("PKCS12");

	        keyStore.load(
	                is,
	                keystorePassword.toCharArray());

	        Certificate certificate =
	                keyStore.getCertificate(keyAlias);

	        return certificate.getPublicKey();
	    }
	}
	private static PrivateKey loadPrivateKey(
	        String keystoreFile,
	        String keystorePassword,
	        String keyAlias)
	        throws Exception {

	    try (InputStream is =
	                 gen6.class.getClassLoader()
	                         .getResourceAsStream(
	                                 keystoreFile)) {

	        KeyStore keyStore =
	                KeyStore.getInstance("PKCS12");

	        keyStore.load(
	                is,
	                keystorePassword.toCharArray());

	        return (PrivateKey)
	                keyStore.getKey(
	                        keyAlias,
	                        keystorePassword.toCharArray());
	    }
	}
	public static String generateDigitalSignature(
	        String payload,
	        String keystoreFile,
	        String keystorePassword,
	        String keyAlias,
	        String publicCertPath) throws Exception {

	    PrivateKey privateKey =
	            loadPrivateKey(
	                    keystoreFile,
	                    keystorePassword,
	                    keyAlias);

	    Signature signature =
	            Signature.getInstance("SHA256withRSA");

	    signature.initSign(privateKey);

	    signature.update(
	            payload.getBytes(StandardCharsets.UTF_8));

	    return Base64.getEncoder()
	            .encodeToString(signature.sign());
	}
	private static PublicKey loadPublicKeyFromCrt(String publicCertPath)
	        throws Exception {

	    try (InputStream is =
	            gen6.class.getClassLoader()
	                    .getResourceAsStream(publicCertPath)) {

	        if (is == null) {
	            throw new RuntimeException(
	                    "Cannot find certificate: " + publicCertPath);
	        }

	        CertificateFactory factory =
	                CertificateFactory.getInstance("X.509");

	        X509Certificate certificate =
	                (X509Certificate) factory.generateCertificate(is);

	        return certificate.getPublicKey();
	    }
	}
	public static boolean verifyDigitalSignature(
	        String payload,
	        String signatureString,
	        String publicCertPath) throws Exception {

	    PublicKey publicKey =
	            loadPublicKeyFromCrt(publicCertPath);

	    Signature signature =
	            Signature.getInstance("SHA256withRSA");

	    signature.initVerify(publicKey);

	    signature.update(
	            payload.getBytes(StandardCharsets.UTF_8));

	    return signature.verify(
	            Base64.getDecoder().decode(signatureString));
	}
	public static void main(String[] args) {

	    try {
	    	String keystoreFile = "keystore.jks";
	    	String keystorePassword = "sbieis2025";
	        String keyAlias = "eis2";
	     // certificate path
	     String publicCertPath = "public.crt";

	    	String secretKey =
                    generateDynamicKey();
	    	 System.out.println(
	                    "Original AES Key:\n"
	                            + secretKey);
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
            System.out.println(
                    "\nEncrypted Payload:\n"
                            + encryptedPayload);
            String decryptedPayload =
                    decryptJsonRequest(
                            encryptedPayload,
                            secretKey);
            System.out.println(
                    "\nDecrypted Payload:\n"
                            + decryptedPayload);
	        String encryptedAESKey =
	                encryptAESKey(
	                        secretKey,
	                        keystoreFile,
	                        keystorePassword,
	                        keyAlias);

	        String decryptedAESKey =
	                decryptAESKey(
	                        encryptedAESKey,
	                        keystoreFile,
	                        keystorePassword,
	                        keyAlias);

	        System.out.println("\nEncrypted AES Key:\n " + encryptedAESKey);
	        System.out.println("\nDecrypted AES Key: \n" + decryptedAESKey);
	        String digitalSignature =
	                generateDigitalSignature(
	                        jsonPayload,
	                        keystoreFile,
	                        keystorePassword,
	                        keyAlias,
	                        publicCertPath);

	        boolean valid =
	                verifyDigitalSignature(
	                        jsonPayload,
	                        digitalSignature,
	                        publicCertPath);
	        System.out.println("\nVailidate Digisign: \n" + valid);
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
}