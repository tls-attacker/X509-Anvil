/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.constants;

import de.rub.nds.protocol.constants.SignatureAlgorithm;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public enum SignatureAlgorithmLengthPair {
    RSA_512(SignatureAlgorithm.RSA_PKCS1, 512),
    RSA_1024(SignatureAlgorithm.RSA_PKCS1, 1024),
    RSA_2048(SignatureAlgorithm.RSA_PKCS1, 2048),
    RSA_4096(SignatureAlgorithm.RSA_PKCS1, 4096),
    // RSA_8192(KeyType.RSA, 8192),

    DSA_512(SignatureAlgorithm.DSA, 512),
    DSA_1024(SignatureAlgorithm.DSA, 1024),
    DSA_2048(SignatureAlgorithm.DSA, 2048),
    DSA_3072(SignatureAlgorithm.DSA, 3072),

    ECDSA_160(SignatureAlgorithm.ECDSA, 192),
    ECDSA_224(SignatureAlgorithm.ECDSA, 224),
    ECDSA_256(SignatureAlgorithm.ECDSA, 256),
    ECDSA_384(SignatureAlgorithm.ECDSA, 384),;

    private final SignatureAlgorithm signatureAlgorithm;
    private final int keyLength;

    SignatureAlgorithmLengthPair(SignatureAlgorithm signatureAlgorithm, int keyLength) {
        this.signatureAlgorithm = signatureAlgorithm;
        this.keyLength = keyLength;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public static List<Integer> getKeyLengths(SignatureAlgorithm keyType) {
        return Arrays.stream(SignatureAlgorithmLengthPair.values()).filter(p -> p.signatureAlgorithm == keyType)
            .map(SignatureAlgorithmLengthPair::getKeyLength).collect(Collectors.toList());
    }

    public static SignatureAlgorithmLengthPair get(SignatureAlgorithm signatureAlgorithm, int keyLength) {
        return Arrays.stream(SignatureAlgorithmLengthPair.values()).filter(p -> p.signatureAlgorithm == signatureAlgorithm && p.keyLength == keyLength)
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException("KeyType - length combination is not supported"));
    }
}
