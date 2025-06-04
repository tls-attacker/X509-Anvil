/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.anvil;

import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.anvilcore.model.parameter.ParameterType;

public enum X509AnvilParameterType implements ParameterType {
    CHAIN_LENGTH,
    VERSION,
    SERIAL_NUMBER,
    KEY_TYPE,
    NOT_BEFORE,
    NOT_AFTER,
    CN_TYPE,
    EXTENSIONS_PRESENT,

    // BasicConstraints extension //TODO: Apply in tests
    EXT_BASIC_CONSTRAINTS_PRESENT,
    EXT_BASIC_CONSTRAINTS_CRITICAL,
    EXT_BASIC_CONSTRAINTS_CA,
    EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT_PRESENT,
    EXT_BASIC_CONSTRAINTS_PATHLEN_CONSTRAINT,

    ;

    @Override
    public DerivationParameter getInstance(ParameterScope scope) {
        return X509AnvilParameterFactory.getInstance(new ParameterIdentifier(this, scope));
    }

    @Override
    public String toString() {
        return this.name().toLowerCase();
    }
}
