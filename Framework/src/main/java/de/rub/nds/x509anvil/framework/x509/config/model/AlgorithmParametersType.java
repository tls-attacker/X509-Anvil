/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.config.model;

public enum AlgorithmParametersType {
    NO_PARAMETERS, // No parameters indicated by omitted parameters tag in AlgorithmIdentifier sequence
    NULL_PARAMETER, // No parameters indicated by a parameters tag of type NULL
    PARAMETERS_PRESENT // Encode provided parameters
}
