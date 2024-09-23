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
