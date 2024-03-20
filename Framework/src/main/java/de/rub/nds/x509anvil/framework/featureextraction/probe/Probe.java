/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;

public interface Probe {
    ProbeResult execute() throws ProbeException;
}
