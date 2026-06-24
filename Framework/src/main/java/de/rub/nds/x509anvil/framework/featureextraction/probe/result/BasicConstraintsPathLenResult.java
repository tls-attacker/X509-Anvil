package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

public class BasicConstraintsPathLenResult extends FeatureSupportedProbeResult{

    private final int pathLen;

    public BasicConstraintsPathLenResult(boolean supported, int pathLen) {
        super(ProbeType.BASIC_CONSTRAINTS_PATH_LEN, supported);

        this.pathLen = pathLen;
    }

    public int getPathLen() {
        return pathLen;
    }
}
