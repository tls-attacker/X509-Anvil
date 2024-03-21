/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;

import java.security.KeyPair;

public class EntitySignatureAlgorithmProbe extends SimpleProbe {
    private final SignatureAlgorithm signatureAlgorithm;

    public EntitySignatureAlgorithmProbe(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig = X509CertificateConfigUtil.createBasicConfig(2);
        X509CertificateConfig entity = x509CertificateChainConfig.getEntityCertificateConfig();
        entity.setKeyType(signatureAlgorithm.getKeyType());
        entity.setHashAlgorithm(signatureAlgorithm.getHashAlgorithm());
        KeyPair keyPair =
            X509CertificateConfigUtil.generateKeyPair(signatureAlgorithm.getKeyType(), entity.getCertificateName());
        entity.setKeyPair(keyPair);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new SignatureAlgorithmProbeResult(signatureAlgorithm, verifierResult.isValid());
    }
}
