package de.rub.nds.x509anvil.framework.anvil.parameter.value;

import java.util.Arrays;
import java.util.Objects;

public class BitString {
    private byte[] bytes;
    private int unusedBits;

    public BitString(byte[] bytes, int unusedBits) {
        this.bytes = bytes;
        this.unusedBits = unusedBits;
    }

    public byte[] getBytes() {
        return bytes;
    }

    public void setBytes(byte[] bytes) {
        this.bytes = bytes;
    }

    public int getUnusedBits() {
        return unusedBits;
    }

    public void setUnusedBits(int unusedBits) {
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
}
