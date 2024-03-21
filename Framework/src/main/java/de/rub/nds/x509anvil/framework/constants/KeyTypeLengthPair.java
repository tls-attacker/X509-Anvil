/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.constants;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum KeyTypeLengthPair {
    RSA_512(KeyType.RSA, 512),
    RSA_1024(KeyType.RSA, 1024),
    RSA_2048(KeyType.RSA, 2048),
    RSA_4096(KeyType.RSA, 4096),
    // RSA_8192(KeyType.RSA, 8192),

    DSA_512(KeyType.DSA, 512),
    DSA_1024(KeyType.DSA, 1024),
    DSA_2048(KeyType.DSA, 2048),
    DSA_3072(KeyType.DSA, 3072),

    ECDSA_160(KeyType.ECDSA, 192),
    ECDSA_224(KeyType.ECDSA, 224),
    ECDSA_256(KeyType.ECDSA, 256),
    ECDSA_384(KeyType.ECDSA, 384),;

    private final KeyType keyType;
    private final int keyLength;

    KeyTypeLengthPair(KeyType keyType, int keyLength) {
        this.keyType = keyType;
        this.keyLength = keyLength;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public static List<Integer> getKeyLengths(KeyType keyType) {
        return Arrays.stream(KeyTypeLengthPair.values()).filter(p -> p.keyType == keyType)
            .map(KeyTypeLengthPair::getKeyLength).collect(Collectors.toList());
    }

    public static KeyTypeLengthPair get(KeyType keyType, int keyLength) {
        return Arrays.stream(KeyTypeLengthPair.values()).filter(p -> p.keyType == keyType && p.keyLength == keyLength)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("KeyType - length combination is not supported"));
    }
}
