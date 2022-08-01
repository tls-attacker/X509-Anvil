package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class DigitalSignatureKeyUsageRequiredProbeResult extends ProbeResult {
    private final boolean required;

    public DigitalSignatureKeyUsageRequiredProbeResult(boolean required) {
        super(ProbeType.DIGITAL_SIGNATURE_KEY_USAGE_REQUIRED);
        this.required = required;
    }

    public boolean isRequired() {
        return required;
    }
}
