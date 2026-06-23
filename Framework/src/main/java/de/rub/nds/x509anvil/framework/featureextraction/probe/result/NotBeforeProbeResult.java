package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.anvil.parameter.value.NotBeforeValue;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class NotBeforeProbeResult extends FeatureSupportedProbeResult{

    private final NotBeforeValue notBeforeValue;

    public NotBeforeProbeResult(NotBeforeValue notBeforeValue, boolean supported) {
        super(ProbeType.NOTBEFORE, supported);

        this.notBeforeValue = notBeforeValue;
    }

    public NotBeforeValue getNotBeforeValue() {
        return notBeforeValue;
    }
}
