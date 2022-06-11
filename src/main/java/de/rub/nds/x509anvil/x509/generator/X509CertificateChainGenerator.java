package de.rub.nds.x509anvil.x509.generator;

import de.rub.nds.x509anvil.exception.CertificateGeneratorException;
import de.rub.nds.x509anvil.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.x509.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.X509Certificate;

import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainGenerator {
    private final X509CertificateChainConfig certificateChainConfig;

    private final List<X509Certificate> generatedCertificates = new ArrayList<>();

    public X509CertificateChainGenerator(X509CertificateChainConfig certificateChainConfig) {
        this.certificateChainConfig = certificateChainConfig;
    }

    public void generateCertificateChain() throws CertificateGeneratorException {
        List<X509CertificateConfig> certificateConfigs = certificateChainConfig.getCertificateConfigs();
        if (certificateConfigs.isEmpty()) {
            throw new CertificateGeneratorException("No certificate config specified");
        }

        // Handle root certificate
        generateSingleCertificate(certificateConfigs.get(0), null);

        // Handle other certificates
        for (int i = 1; i < certificateConfigs.size(); i++) {
            generateSingleCertificate(certificateConfigs.get(i), certificateConfigs.get(i-1));
        }
    }

    public List<X509Certificate> retrieveCertificateChain() {
        return this.generatedCertificates;
    }

    private void generateSingleCertificate(X509CertificateConfig config, X509CertificateConfig nextInChainConfig) throws CertificateGeneratorException {
        X509CertificateGenerator x509CertificateGenerator = new X509CertificateGenerator(config, nextInChainConfig);
        x509CertificateGenerator.generateCertificate();
        this.generatedCertificates.add(x509CertificateGenerator.retrieveX509Certificate());
    }
}
