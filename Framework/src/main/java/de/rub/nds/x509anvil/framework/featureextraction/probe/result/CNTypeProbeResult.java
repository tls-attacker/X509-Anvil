package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;

public class CNTypeProbeResult extends FeatureSupportedProbeResult{

    private final DirectoryStringChoiceType directoryStringChoiceType;

    public CNTypeProbeResult(DirectoryStringChoiceType directoryStringChoiceType, boolean supported) {
        super(ProbeType.CNTYPE, supported);

        this.directoryStringChoiceType = directoryStringChoiceType;
    }

    public DirectoryStringChoiceType getDirectoryStringChoiceType() {
        return directoryStringChoiceType;
    }
}
