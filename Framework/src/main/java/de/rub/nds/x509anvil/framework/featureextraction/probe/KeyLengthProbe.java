/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.KeyLengthProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.security.KeyPair;

public class KeyLengthProbe extends SimpleProbe {
    private final X509SignatureAlgorithm signatureAlgorithm;
    private final int keyLength;
    private final boolean isEntity;

    public KeyLengthProbe(X509SignatureAlgorithm signatureAlgorithm, int keyLength, boolean isEntity) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyLength = keyLength;
        this.isEntity = isEntity;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
            X509CertificateConfigUtil.createBasicConfig(isEntity ? 2 : 3);

        X509CertificateConfig certificateConfig;
        if (isEntity) {
            certificateConfig = x509CertificateChainConfig.getEntityCertificateConfig();
        } else {
            certificateConfig = x509CertificateChainConfig.getIntermediateCertificateConfigs().get(0);
        }
        certificateConfig.setSignatureAlgorithm(signatureAlgorithm);
        // TODO: fix key generation with given key length
        KeyPair keyPair = X509CertificateConfigUtil.generateKeyPair(signatureAlgorithm.getSignatureAlgorithm(), keyLength);
        certificateConfig.applyKeyPair(keyPair);
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new KeyLengthProbeResult(signatureAlgorithm, keyLength, isEntity, verifierResult.isValid());
    }
}
