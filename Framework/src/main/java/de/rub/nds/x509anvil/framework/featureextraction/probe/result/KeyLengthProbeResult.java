/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

public class KeyLengthProbeResult extends FeatureSupportedProbeResult {
    private final X509SignatureAlgorithm signatureAlgorithm;
    private final int keyLength;
    private final boolean isEntity;

    public KeyLengthProbeResult(
            X509SignatureAlgorithm signatureAlgorithm,
            int keyLength,
            boolean isEntity,
            boolean supported) {
        super(ProbeType.KEY_LENGTH, supported);
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyLength = keyLength;
        this.isEntity = isEntity;
    }

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public boolean isEntity() {
        return isEntity;
    }
}
