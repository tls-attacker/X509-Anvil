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
    ENTITY_CERT,
    INTERMEDIATE_CERT,
    ROOT_CERT;

    static ParameterScope[] getCertificateScopes() {
        return new ParameterScope[] { ENTITY_CERT, INTERMEDIATE_CERT, ROOT_CERT };
    }
}
