/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import java.util.ArrayList;
import java.util.List;

public class X509CertificateChainGenerator {
    private final X509CertificateChainConfig certificateChainConfig;

    // TODO: should be used, but can probably also simplified

    private final List<X509Certificate> generatedCertificates = new ArrayList<>();

    public X509CertificateChainGenerator(X509CertificateChainConfig certificateChainConfig) {
        this.certificateChainConfig = certificateChainConfig;
    }

    public void generateCertificateChain() throws CertificateGeneratorException {
        if (!certificateChainConfig.isInitialized()) {
            throw new CertificateGeneratorException("X509CertificateChainConfig is not initialized");
        }

        X509CertificateConfig previousConfig = null;
        for (X509CertificateConfig certificateConfig : certificateChainConfig.getCertificateConfigList()) {
            generateSingleCertificate(certificateConfig, previousConfig);
            previousConfig = certificateConfig;
        }
    }

    public List<X509Certificate> retrieveCertificateChain() {
        return this.generatedCertificates;
    }

    private void generateSingleCertificate(X509CertificateConfig config, X509CertificateConfig signerConfig) {

        // set signature signing keys to keys from signer config unless self-signed

        if (signerConfig != null && !config.isSelfSigned()) {
            // rsa
            config.setDefaultIssuerRsaModulus(signerConfig.getDefaultSubjectRsaModulus());
            config.setDefaultIssuerRsaPrivateExponent(signerConfig.getDefaultSubjectRsaPrivateExponent());
            config.setDefaultIssuerRsaPublicKey(signerConfig.getDefaultSubjectRsaPublicKey());
            // dsa
            config.setDefaultIssuerDsaGenerator(signerConfig.getDefaultSubjectDsaGenerator());
            config.setDefaultIssuerDsaPublicKey(signerConfig.getDefaultSubjectDsaPublicKey());
            config.setDefaultIssuerDsaPrimeP(signerConfig.getDefaultSubjectDsaPrimeP());
            config.setDefaultIssuerDsaPrimeQ(signerConfig.getDefaultSubjectDsaPrimeQ());
            config.setDefaultIssuerDsaNonce(signerConfig.getDefaultSubjectDsaNonce());
            config.setDefaultIssuerDsaPrivateKey(signerConfig.getDefaultSubjectDsaPrivateKey());
            // ecdsa
            config.setDefaultIssuerEcPrivateKey(signerConfig.getDefaultSubjectEcPrivateKey());
            config.setDefaultIssuerEcPublicKey(signerConfig.getDefaultSubjectEcPublicKey());
            config.setDefaultIssuerNamedCurve(signerConfig.getDefaultSubjectNamedCurve());
            config.setDefaultEcPointFormat(signerConfig.getDefaultEcPointFormat());
            config.setDefaultIssuerEcPrivateKey(signerConfig.getDefaultSubjectEcPrivateKey());
        }
        X509Certificate certificate = new X509Certificate("cert", config);
        this.generatedCertificates.add(certificate);
        certificate.getPreparator(new X509Chooser(config, new X509Context())).prepare();
    }
}
