/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.constants;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureHashAlgorithmKeyLengthPair {

    private X509SignatureAlgorithm signatureAndHashAlgorithm;

    private int keyLength;

    public SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm signatureAndHashAlgorithm, int keyLength) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
        this.keyLength = keyLength;
    }

    public X509SignatureAlgorithm getSignatureAndHashAlgorithm() {
        return signatureAndHashAlgorithm;
    }

    public void setSignatureAndHashAlgorithm(X509SignatureAlgorithm signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    /**
     * Generates all possible combinations of signature algorithm, hash algorithm, and key length.
     */
    // not implemented in enum because of high number of combinations
    public static List<SignatureHashAlgorithmKeyLengthPair> generateAllPossibilities() {
        List<SignatureHashAlgorithmKeyLengthPair> pairs = new LinkedList<>();

        for (X509SignatureAlgorithm signatureAlgorithm : X509SignatureAlgorithm.values()) {
            switch (signatureAlgorithm.getSignatureAlgorithm()) {
                case RSA_PKCS1:
                case RSA_SSA_PSS:
                    pairs.addAll(Arrays.stream(RsaKeyLength.values())
                        .map(length -> new SignatureHashAlgorithmKeyLengthPair(signatureAlgorithm, length.getLength()))
                        .collect(Collectors.toList()));
                    break;
                case DSA:
                    pairs.addAll(Arrays.stream(DsaKeyLength.values())
                        .map(length -> new SignatureHashAlgorithmKeyLengthPair(signatureAlgorithm, length.getLength()))
                        .collect(Collectors.toList()));
                    break;
                case ECDSA:
                    pairs.addAll(Arrays.stream(EcdsaKeyLength.values())
                        .map(length -> new SignatureHashAlgorithmKeyLengthPair(signatureAlgorithm, length.getLength()))
                        .collect(Collectors.toList()));
                    break;
                default:
                    throw new UnsupportedOperationException(
                        "Algorithm " + signatureAlgorithm.getSignatureAlgorithm() + " not supported.");
            }
        }
        return pairs;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAndHashAlgorithm.getSignatureAlgorithm();
    }

    public HashAlgorithm getHashAlgorithm() {
        return signatureAndHashAlgorithm.getHashAlgorithm();
    }

    @Override
    public String toString() {
        return "SignatureHashAlgorithmKeyLengthPair{" + "signatureAndHashAlgorithm=" + signatureAndHashAlgorithm
            + ", keyLength=" + keyLength + '}';
    }
}
