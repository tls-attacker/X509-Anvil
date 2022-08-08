package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class KeyLengthProbeResult extends FeatureSupportedProbeResult {
    private final SignatureAlgorithm signatureAlgorithm;
    private final int keyLength;

    public KeyLengthProbeResult(SignatureAlgorithm signatureAlgorithm, int keyLength, boolean supported) {
        super(ProbeType.KEY_LENGTH, supported);
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyLength = keyLength;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }
}
