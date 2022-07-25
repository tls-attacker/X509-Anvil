package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.ProbeType;

public abstract class FeatureSupportedProbeResult extends ProbeResult {
    private final boolean supported;

    public FeatureSupportedProbeResult(ProbeType probeType, boolean supported) {
        super(probeType);
        this.supported = supported;
    }

    public boolean isSupported() {
        return supported;
    }
}
