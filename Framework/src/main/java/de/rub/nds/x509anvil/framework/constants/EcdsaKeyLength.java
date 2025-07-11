/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.constants;

public enum EcdsaKeyLength {
    ECDSA_160(192),
    ECDSA_224(224),
    ECDSA_256(256),
    ECDSA_384(384),
    ;

    private final int length;

    EcdsaKeyLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }
}
