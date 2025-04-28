/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.featureextraction.probe.result;

import de.rub.nds.x509anvil.framework.featureextraction.probe.ProbeType;

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
