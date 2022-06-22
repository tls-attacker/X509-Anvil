/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.model;

public enum ParameterScope {
    GLOBAL,
    CERT_ENTITY,
    CERT_INTERMEDIATE,
    CERT_ROOT;

    static ParameterScope[] getCertificateScopes() {
        return new ParameterScope[] {CERT_ENTITY, CERT_INTERMEDIATE, CERT_ROOT};
    }
}
