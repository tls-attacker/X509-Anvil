package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.ProbeType;

public class VersionProbeResult extends FeatureSupportedProbeResult {
    private final int version;

    public VersionProbeResult(int version, boolean supported) {
        super(ProbeType.VERSION, supported);
        this.version = version;
    }

    public int getVersion() {
        return version;
    }
}
