/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.security.KeyPair;

public class EntitySignatureAlgorithmProbe extends SimpleProbe {
    private final X509SignatureAlgorithm signatureAlgorithm;

    public EntitySignatureAlgorithmProbe(X509SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig = X509CertificateConfigUtil.createBasicConfig(2);
        X509CertificateConfig entity = x509CertificateChainConfig.getEntityCertificateConfig();
        entity.setSignatureAlgorithm(signatureAlgorithm);
        // TODO: should be unnecessary as correct key already present
        // KeyPair keyPair = X509CertificateConfigUtil.generateKeyPair(signatureAlgorithm.getSignatureAlgorithm(),
        // entity.getCertificateName());
        // entity.applyKeyPair(keyPair);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new SignatureAlgorithmProbeResult(signatureAlgorithm, verifierResult.isValid());
    }
}
