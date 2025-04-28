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
