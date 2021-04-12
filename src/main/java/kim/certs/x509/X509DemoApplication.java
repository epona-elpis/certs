package kim.certs.x509;

import kim.certs.x509.builder.KeyPairBuilder;
import kim.certs.x509.builder.X509CertificateBuilder;
import kim.certs.x509.printer.PemPrinter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@SpringBootApplication
public class X509DemoApplication {

	@Autowired
	private KeyPairBuilder keyPairBuilder;

	@Autowired
	private X509CertificateBuilder X509CertificateBuilder;

	@Autowired
	private PemPrinter pemPrinter;

	public static void main(String[] args) {
		SpringApplication.run(X509DemoApplication.class, args);
	}

	@PostConstruct
	private void createAndPrivateKeyAndCertificate() throws NoSuchAlgorithmException, CertificateException, IOException, OperatorCreationException {
		KeyPair keyPair = keyPairBuilder
				.withAlgorithm("RSA")
				.withKeySize(4096)
				.build();

		X509Certificate cert = X509CertificateBuilder
				.withKeyPair(keyPair)
				.withHashAlogrithm("SHA256withRSA")
				.withCN("kim")
				.withDays(365)
				.build();

		//print private key
		PrivateKey privateKey = keyPair.getPrivate();
		String privateKeyFormat = privateKey.getFormat(); //not RSA so not going to print it
		System.out.println(pemPrinter.privateKeyToPem(new PemObject("RSA PRIVATE KEY", privateKey.getEncoded())));

		//print certificate
		System.out.println(pemPrinter.x509CertificateToPem(cert));
	}
}
