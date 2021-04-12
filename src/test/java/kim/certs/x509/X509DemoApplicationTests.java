package kim.certs.x509;

import kim.certs.x509.builder.KeyPairBuilder;
import kim.certs.x509.builder.X509CertificateBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertNotNull;

@SpringBootTest
class X509DemoApplicationTests {
	@Autowired
	private KeyPairBuilder keyPairBuilder;

	@Autowired
	private X509CertificateBuilder X509CertificateBuilder;

	@Test
	void contextLoads() {
		assertNotNull(keyPairBuilder);
		assertNotNull(X509CertificateBuilder);
	}

}
