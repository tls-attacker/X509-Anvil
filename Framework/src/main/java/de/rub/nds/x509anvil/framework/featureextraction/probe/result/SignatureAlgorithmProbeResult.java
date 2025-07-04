/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class SignatureAlgorithmProbeResult extends FeatureSupportedProbeResult {
    private final SignatureHashAlgorithmKeyLengthPair signatureHashAlgorithmKeyLengthPair;

    public SignatureAlgorithmProbeResult(
            SignatureHashAlgorithmKeyLengthPair signatureHashAlgorithmKeyLengthPair,
            boolean supported) {
        super(ProbeType.SIGNATURE_ALGORITHM, supported);
        this.signatureHashAlgorithmKeyLengthPair = signatureHashAlgorithmKeyLengthPair;
    }

    public SignatureHashAlgorithmKeyLengthPair getSignatureAlgorithm() {
        return signatureHashAlgorithmKeyLengthPair;
    }
}
