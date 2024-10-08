package de.rub.nds.x509anvil.framework.constants;

import de.rub.nds.protocol.constants.SignatureAlgorithm;

public enum EcdsaKeyLength {

    ECDSA_160(192),
    ECDSA_224(224),
    ECDSA_256(256),
    ECDSA_384(384),;
    
    private final int length;

    EcdsaKeyLength(int length) {
        this.length = length;
    }

    public int getLength() {
        return length;
    }
}
