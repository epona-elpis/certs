package kim.certs.x509.printer;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

@Component
public class PemPrinter {

    public String privateKeyToPem(final PemObject pemObject ) throws IOException, IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(pemObject);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }

    public String x509CertificateToPem(final X509Certificate cert) throws IOException, IOException {
        final StringWriter writer = new StringWriter();
        final JcaPEMWriter pemWriter = new JcaPEMWriter(writer);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        pemWriter.close();
        return writer.toString();
    }
}
