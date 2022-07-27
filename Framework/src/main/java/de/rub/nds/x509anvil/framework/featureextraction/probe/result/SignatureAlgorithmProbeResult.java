package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.ProbeType;

public class SignatureAlgorithmProbeResult extends FeatureSupportedProbeResult {
    private final SignatureAlgorithm signatureAlgorithm;

    public SignatureAlgorithmProbeResult(SignatureAlgorithm signatureAlgorithm, boolean supported) {
        super(ProbeType.SIGNATURE_ALGORITHM, supported);
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }
}
