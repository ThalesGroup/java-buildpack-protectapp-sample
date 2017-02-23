package io.pivotal.protectapp;

import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAEParameterSpec;
import com.ingrian.security.nae.NAEPrivateKey;
import com.ingrian.security.nae.NAEPublicKey;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

    @Bean
    Cipher decryptionCipher(PrivateKey privateKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA", "IngrianProvider");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher;
    }

    @Bean
    Cipher encryptionCipher(PublicKey publicKey) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA", "IngrianProvider");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher;
    }

    @Bean
    String keyName() throws GeneralSecurityException {
        String keyName = String.format("%s%s", "protectapp-sample-", new BigInteger(25, new SecureRandom()).toString(32));

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "IngrianProvider");
        keyPairGenerator.initialize(new NAEParameterSpec(keyName, false, true));
        keyPairGenerator.generateKeyPair();

        return keyName;
    }

    @Bean
    NAEPrivateKey privateKey(String keyName) {
        return NAEKey.getPrivateKey(keyName);
    }

    @Bean
    NAEPublicKey publicKey(String keyName) {
        return NAEKey.getPublicKey(keyName);
    }

    @Bean
    Signature signingSignature(PrivateKey privateKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSA");
        signature.initSign(privateKey);
        return signature;
    }

    @Bean
    Signature verificationSignature(PublicKey publicKey) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("RSA");
        signature.initVerify(publicKey);
        return signature;
    }

}
