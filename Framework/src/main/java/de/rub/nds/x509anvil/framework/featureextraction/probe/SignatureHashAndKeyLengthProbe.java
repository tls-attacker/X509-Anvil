/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.SignatureAlgorithmProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.key.CachedKeyPairGenerator;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;

public class SignatureHashAndKeyLengthProbe extends SimpleProbe {
    private final SignatureHashAlgorithmKeyLengthPair signatureHashAlgorithmKeyLengthPair;
    private final boolean entity;

    public SignatureHashAndKeyLengthProbe(SignatureHashAlgorithmKeyLengthPair signatureHashAlgorithmKeyLengthPair,
        boolean entity) {
        this.signatureHashAlgorithmKeyLengthPair = signatureHashAlgorithmKeyLengthPair;
        this.entity = entity;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig = X509CertificateConfigUtil.createBasicConfig(3);
        X509CertificateConfig config;
        if (entity) {
            config = x509CertificateChainConfig.getEntityCertificateConfig();
            CachedKeyPairGenerator.generateNewKeys(signatureHashAlgorithmKeyLengthPair, config, "entity");
        } else {
            config = x509CertificateChainConfig.getLastSigningConfig();
            CachedKeyPairGenerator.generateNewKeys(signatureHashAlgorithmKeyLengthPair, config, "inter0");
        }
        // set signature hash and key length
        // TODO: for RSA_PSS we always use the same hash algorithm
        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new SignatureAlgorithmProbeResult(signatureHashAlgorithmKeyLengthPair, verifierResult.isValid());
    }
}
