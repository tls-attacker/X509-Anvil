/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.constants;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class SignatureHashAlgorithmKeyLengthPair {

    @JsonProperty("SignatureAndHashAlgorithm")
    private X509SignatureAlgorithm signatureAndHashAlgorithm;

    @JsonProperty("KeyLength")
    private int keyLength;

    public SignatureHashAlgorithmKeyLengthPair(
            X509SignatureAlgorithm signatureAndHashAlgorithm, int keyLength) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
        this.keyLength = keyLength;
    }

    /**
     * Constructor that only specifies the Signature and Hash Algorithm. Key length is set to a
     * default value: 2048 for RSA, 256 for ECDSA, and 1024 for DSA.
     *
     * @param signatureAndHashAlgorithm The signature and hash algorithm to use.
     */
    public SignatureHashAlgorithmKeyLengthPair(X509SignatureAlgorithm signatureAndHashAlgorithm) {
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
        this.keyLength =
                switch (signatureAndHashAlgorithm.getSignatureAlgorithm()) {
                    case SignatureAlgorithm.RSA_PKCS1, SignatureAlgorithm.RSA_SSA_PSS ->
                            RsaKeyLength.RSA_2048.getLength();
                    case SignatureAlgorithm.DSA -> DsaKeyLength.DSA_1024.getLength();
                    case SignatureAlgorithm.ECDSA -> EcdsaKeyLength.ECDSA_256.getLength();
                    default ->
                            throw new UnsupportedOperationException(
                                    "Algorithm "
                                            + signatureAndHashAlgorithm.getSignatureAlgorithm()
                                            + " not supported.");
                };
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
                    pairs.addAll(
                            Arrays.stream(RsaKeyLength.values())
                                    .map(
                                            length ->
                                                    new SignatureHashAlgorithmKeyLengthPair(
                                                            signatureAlgorithm, length.getLength()))
                                    .collect(Collectors.toList()));
                    break;
                case DSA:
                    pairs.addAll(
                            Arrays.stream(DsaKeyLength.values())
                                    .map(
                                            length ->
                                                    new SignatureHashAlgorithmKeyLengthPair(
                                                            signatureAlgorithm, length.getLength()))
                                    .collect(Collectors.toList()));
                    break;
                case ECDSA:
                    pairs.addAll(
                            Arrays.stream(EcdsaKeyLength.values())
                                    .map(
                                            length ->
                                                    new SignatureHashAlgorithmKeyLengthPair(
                                                            signatureAlgorithm, length.getLength()))
                                    .collect(Collectors.toList()));
                    break;
                default:
                    throw new UnsupportedOperationException(
                            "Algorithm "
                                    + signatureAlgorithm.getSignatureAlgorithm()
                                    + " not supported.");
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

    @JsonIgnore
    public SignatureAlgorithm getSignatureAlgorithm() {
        return signatureAndHashAlgorithm.getSignatureAlgorithm();
    }

    @JsonIgnore
    public HashAlgorithm getHashAlgorithm() {
        return signatureAndHashAlgorithm.getHashAlgorithm();
    }

    @Override
    public String toString() {
        return "SignatureHashAlgorithmKeyLengthPair{"
                + "signatureAndHashAlgorithm="
                + signatureAndHashAlgorithm
                + ", keyLength="
                + keyLength
                + '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o instanceof SignatureHashAlgorithmKeyLengthPair other) {
            return (keyLength == other.keyLength
                    && signatureAndHashAlgorithm.equals(other.signatureAndHashAlgorithm));
        } else {
            return false;
        }
    }

    @Override
    public int hashCode() {
        return 31 * signatureAndHashAlgorithm.hashCode() + keyLength;
    }
}
