/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.constants;

public enum DsaKeyLength {

    DSA_512(512),
    DSA_1024(1024),
    DSA_2048(2048),
    DSA_3072(3072);

    private final int length;

    DsaKeyLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }
}
