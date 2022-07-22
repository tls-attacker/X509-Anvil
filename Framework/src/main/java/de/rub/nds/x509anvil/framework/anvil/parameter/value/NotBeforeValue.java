package de.rub.nds.x509anvil.framework.anvil.parameter.value;

public enum NotBeforeValue {
    UTC_TIME,
    UTC_TIME_EARLIEST,              // Earliest possible UTCTime data (01.01.1950)
    GENERALIZED_TIME,               // Even though UTC time MUST be used for dates before 2050, the verifier MUST still be able to handle it
    GENERALIZED_TIME_BEFORE_1950    // RFC is not clear about this case
}