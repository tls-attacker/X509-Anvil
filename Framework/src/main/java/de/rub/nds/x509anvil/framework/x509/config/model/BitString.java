/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config.model;

import java.util.Arrays;
import java.util.Objects;

public class BitString {
    private byte[] bytes;
    private byte unusedBits;

    public BitString(byte[] bytes, byte unusedBits) {
        this.bytes = bytes;
        this.unusedBits = unusedBits;
    }

    public BitString(byte[] bytes) {
        this.bytes = bytes;
        this.unusedBits = 0;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte getUnusedBits() {
        return unusedBits;
    }

    public void setUnusedBits(byte unusedBits) {
        this.unusedBits = unusedBits;
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytes, unusedBits);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof BitString)) {
            return false;
        }
        BitString other = (BitString) obj;
        return Arrays.compare(bytes, other.bytes) == 0 && unusedBits == other.unusedBits;
    }

    @Override
    public String toString() {
        return Arrays.toString(bytes) + "-" + unusedBits;
    }
}
