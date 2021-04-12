package kim.certs.x509.builder;

import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;


import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;
@SpringBootTest
public class X509CertificateBuilderTest {
    @Autowired
    private KeyPairBuilder keyPairBuilder;

    @Autowired
    private X509CertificateBuilder X509CertificateBuilder;

    @Test
    public void createSelfSignedCertificateWithBuilder() throws CertificateException, NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeyException, NoSuchProviderException, SignatureException {

         KeyPair keyPair = keyPairBuilder
                 .withAlgorithm("RSA")
                 .withKeySize(4096)
                 .build();

         X509Certificate cert = X509CertificateBuilder
                .withKeyPair(keyPair)
                .withHashAlogrithm("SHA256withRSA")
                .withCN("kim")  //TODO  OU=DEVELOPMENT, O=A_COMPANY, C=UK
                .withDays(365)
                .build();

         cert.checkValidity();
         cert.verify(cert.getPublicKey());

         assertNotNull(cert.getKeyUsage());
         assertNull(cert.getExtendedKeyUsage());
         assertEquals("X.509", cert.getType());
         assertEquals("CN=kim", cert.getSubjectDN().getName());
         assertEquals(cert.getSubjectDN(), cert.getIssuerDN());
         assertEquals("SHA256withRSA", cert.getSigAlgName());
         assertEquals(3, cert.getVersion());

     }


}
