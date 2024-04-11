/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

public class SignatureAlgorithmProbeResult extends FeatureSupportedProbeResult {
    private final X509SignatureAlgorithm signatureAlgorithm;

    public SignatureAlgorithmProbeResult(X509SignatureAlgorithm signatureAlgorithm, boolean supported) {
        super(ProbeType.SIGNATURE_ALGORITHM, supported);
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public X509SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
