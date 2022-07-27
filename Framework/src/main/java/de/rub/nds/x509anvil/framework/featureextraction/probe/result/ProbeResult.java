package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public abstract class ProbeResult {
    private final ProbeType probeType;

    public ProbeResult(ProbeType probeType) {
        this.probeType = probeType;
    }

    public ProbeType getProbeType() {
        return probeType;
    }
}
