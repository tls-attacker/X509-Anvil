/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainGenerator {
    private final X509CertificateChainConfig certificateChainConfig;
    private final List<X509CertificateModifier> certificateModifiers = new ArrayList<>();

    private final List<X509Certificate> generatedCertificates = new ArrayList<>();

    public X509CertificateChainGenerator(X509CertificateChainConfig certificateChainConfig) {
        this.certificateChainConfig = certificateChainConfig;
    }

    public void addModifier(X509CertificateModifier x509CertificateModifier) {
        certificateModifiers.add(x509CertificateModifier);
    }

    public void generateCertificateChain() throws CertificateGeneratorException {
        if (!certificateChainConfig.isInitialized()) {
            throw new CertificateGeneratorException("X509CertificateChainConfig is not initialized");
        }

        X509CertificateConfig previousConfig = null;
        for (X509CertificateConfig certificateConfig : X509CertificateConfigUtil
            .expandCertificateConfigs(certificateChainConfig)) {
            generateSingleCertificate(certificateConfig, previousConfig);
            previousConfig = certificateConfig;
        }
    }

    public List<X509Certificate> retrieveCertificateChain() {
        return this.generatedCertificates;
    }

    private void generateSingleCertificate(X509CertificateConfig config, X509CertificateConfig signerConfig)
        throws CertificateGeneratorException {
        X509CertificateGenerator x509CertificateGenerator =
            new X509CertificateGenerator(config, signerConfig, certificateModifiers);
        x509CertificateGenerator.generateCertificate();
        this.generatedCertificates.add(x509CertificateGenerator.retrieveX509Certificate());
    }
}
