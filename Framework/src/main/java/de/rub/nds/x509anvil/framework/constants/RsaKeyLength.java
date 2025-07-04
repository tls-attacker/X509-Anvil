/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.constants;

public enum RsaKeyLength {
    RSA_512(512),
    RSA_1024(1024),
    RSA_2048(2048),
    RSA_4096(4096);

    private final int length;

    RsaKeyLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }
}
