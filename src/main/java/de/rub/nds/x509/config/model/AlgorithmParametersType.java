package de.rub.nds.x509.config.model;

public enum AlgorithmParametersType {
    NO_PARAMETERS,      // No parameters indicated by omitted parameters tag in AlgorithmIdentifier sequence
    NULL_PARAMETER,     // No parameters indicated by a parameters tag of type NULL
    PARAMETERS_PRESENT  // Encode provided parameters
}
