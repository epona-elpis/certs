package kim.certs.x509.builder;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

@Component
public class X509CertificateBuilder {
    private KeyPair keyPair;
    private String hashAlogrithm;
    private int days;
    private X500Name x500Name;

    public X509CertificateBuilder withKeyPair(final KeyPair keypair)  {
        this.keyPair=keypair;
        return this;
    }

    public X509CertificateBuilder withHashAlogrithm(final String hashAlogrithm){
        this.hashAlogrithm = hashAlogrithm;
        return this;
    }

    public X509CertificateBuilder withDays(final int days){
        this.days = days;
        return this;
    }

    public X509CertificateBuilder withCN(final String cn){
        this.x500Name = new X500Name("CN=" + cn);;
        return this;
    }

    public X509Certificate build() throws CertificateException, CertIOException, OperatorCreationException {
        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider())
                .getCertificate(X509CertificateHolder());
    }

    private X509CertificateHolder X509CertificateHolder() throws OperatorCreationException, CertIOException {
        final Instant now = Instant.now();
        return new JcaX509v3CertificateBuilder(x500Name,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now),
                Date.from(now.plus(Duration.ofDays(days))),
                x500Name,
                keyPair.getPublic())
                .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId())
                .addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
                .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId())
                .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                .build(contentSigner());
    }

    private SubjectKeyIdentifier createSubjectKeyId() throws OperatorCreationException {
        return new X509ExtensionUtils(digestCalculator())
                .createSubjectKeyIdentifier(publicKeyInfo());
    }

     private AuthorityKeyIdentifier createAuthorityKeyId() throws OperatorCreationException {
        return new X509ExtensionUtils(digestCalculator())
                .createAuthorityKeyIdentifier(publicKeyInfo());
    }

    private DigestCalculator digestCalculator() throws OperatorCreationException {
        return new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
    }

    private SubjectPublicKeyInfo publicKeyInfo() {
        return SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
    }

    private ContentSigner contentSigner() throws OperatorCreationException {
        return new JcaContentSignerBuilder(hashAlogrithm)
                .build(keyPair.getPrivate());
    }

}
