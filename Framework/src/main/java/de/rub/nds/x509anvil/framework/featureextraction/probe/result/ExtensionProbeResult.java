package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class ExtensionProbeResult extends FeatureSupportedProbeResult {
    private final ExtensionType extensionType;

    public ExtensionProbeResult(ExtensionType extensionType, boolean supported) {
        super(ProbeType.EXTENSION, supported);
        this.extensionType = extensionType;
    }

    public ExtensionType getExtensionType() {
        return extensionType;
    }
}
