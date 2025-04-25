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

public abstract class ProbeResult {
    private final ProbeType probeType;

    public ProbeResult(ProbeType probeType) {
        this.probeType = probeType;
    }

    public ProbeType getProbeType() {
        return probeType;
    }
}
