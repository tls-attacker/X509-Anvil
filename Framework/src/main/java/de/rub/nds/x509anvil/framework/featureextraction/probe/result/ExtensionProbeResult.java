/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
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
