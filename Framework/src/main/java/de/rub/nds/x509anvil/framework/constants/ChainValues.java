package de.rub.nds.x509anvil.framework.constants;

public enum ChainValues {

    MAX_CHAIN_LENGTH(10),
    MAX_INTERMEDIATE_CERTS_MODELED(MAX_CHAIN_LENGTH.value-2);

    private final int value;

    ChainValues(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
