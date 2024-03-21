/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class KeyLengthProbeResult extends FeatureSupportedProbeResult {
    private final SignatureAlgorithm signatureAlgorithm;
    private final int keyLength;
    private final boolean isEntity;

    public KeyLengthProbeResult(SignatureAlgorithm signatureAlgorithm, int keyLength, boolean isEntity,
        boolean supported) {
        super(ProbeType.KEY_LENGTH, supported);
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyLength = keyLength;
        this.isEntity = isEntity;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public boolean isEntity() {
        return isEntity;
    }
}
