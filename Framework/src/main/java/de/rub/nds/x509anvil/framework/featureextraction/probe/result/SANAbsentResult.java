package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class SANAbsentResult extends FeatureSupportedProbeResult{
    public SANAbsentResult(boolean supported) {
        super(ProbeType.SAN_PRESENT, supported);
    }
}
