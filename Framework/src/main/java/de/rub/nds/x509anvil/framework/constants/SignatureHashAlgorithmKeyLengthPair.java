package de.rub.nds.x509anvil.framework.constants;

import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;

import java.util.List;

public class SignatureHashAlgorithmKeyLengthPair {

    private X509SignatureAlgorithm signatureAndHashAlgorithm;

    private int keyLength;

    public void SignatureAndHashAlgorithm(X509SignatureAlgorithm signatureAndHashAlgorithm, int keyLength) {
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
}
