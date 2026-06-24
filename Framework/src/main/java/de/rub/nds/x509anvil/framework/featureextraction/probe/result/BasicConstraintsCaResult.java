package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class BasicConstraintsCaResult extends FeatureSupportedProbeResult{

    public BasicConstraintsCaResult(boolean supported) {
        super(ProbeType.BASIC_CONSTRAINTS_CA, supported);
    }
}
