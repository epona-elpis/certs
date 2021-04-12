package kim.certs.x509.builder;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

@Component
public class KeyPairBuilder {
    private String algorithm;
    private int keySize;

    public KeyPairBuilder withAlgorithm(final String algorithm){
        this.algorithm = algorithm;
        return this;
    }

    public KeyPairBuilder withKeySize(final int keySize){
        this.keySize = keySize;
        return this;
    }

    public KeyPair build() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }
}
