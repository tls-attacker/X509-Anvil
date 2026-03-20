/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;

public class CommonConstraints {

    public static boolean enabledByParameterCondition(DerivationParameter enabler) {
        if (!enabler.getValueClass().equals(Boolean.class)) {
            throw new IllegalArgumentException(
                    "enabledByParameterCondition expects a Boolean value type");
        }
        if (enabler.getSelectedValue() == null) {
            return false;
        }
        return (Boolean) enabler.getSelectedValue();
    }
}
