package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class ExtensionsPresentResult extends FeatureSupportedProbeResult{
    public ExtensionsPresentResult(boolean supported) {
        super(ProbeType.EXTENSIONS_PRESENT, supported);
    }
}
