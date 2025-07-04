/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.constants;

public enum ChainValues {
    MAX_CHAIN_LENGTH(10),
    MAX_INTERMEDIATE_CERTS_MODELED(MAX_CHAIN_LENGTH.value - 2);

    private final int value;

    ChainValues(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
