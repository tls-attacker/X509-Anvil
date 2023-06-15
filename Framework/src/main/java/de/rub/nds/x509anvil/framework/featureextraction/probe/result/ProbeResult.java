/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
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
