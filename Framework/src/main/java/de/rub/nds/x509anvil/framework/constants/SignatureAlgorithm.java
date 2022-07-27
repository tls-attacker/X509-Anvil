package de.rub.nds.x509anvil.framework.constants;

import java.util.Arrays;

public enum SignatureAlgorithm {
    RSA_NONE(KeyType.RSA, HashAlgorithm.NONE, "1.2.840.113549.1.1.11"),
    RSA_SHA1(KeyType.RSA, HashAlgorithm.SHA1, "1.2.840.113549.1.1.5"),
    RSA_SHA224(KeyType.RSA, HashAlgorithm.SHA224, "1.2.840.113549.1.1.14"),
    RSA_SHA256(KeyType.RSA, HashAlgorithm.SHA256, "1.2.840.113549.1.1.11"),
    RSA_SHA384(KeyType.RSA, HashAlgorithm.SHA384, "1.2.840.113549.1.1.12"),
    RSA_SHA512(KeyType.RSA, HashAlgorithm.SHA512, "1.2.840.113549.1.1.13"),
    RSA_MD2(KeyType.RSA, HashAlgorithm.MD2, "1.2.840.113549.1.1.1.2"),
    RSA_MD4(KeyType.RSA, HashAlgorithm.MD4, "1.2.840.113549.1.1.1.3"),
    RSA_MD5(KeyType.RSA, HashAlgorithm.MD5, "1.2.840.113549.1.1.1.4"),

    DSA_NONE(KeyType.DSA, HashAlgorithm.NONE, "2.16.840.1.101.3.4.3.2"),
    DSA_SHA1(KeyType.DSA, HashAlgorithm.SHA1, "1.2.840.10040.4.3"),
    DSA_SHA224(KeyType.DSA, HashAlgorithm.SHA224, "2.16.840.1.101.3.4.3.1"),
    DSA_SHA256(KeyType.DSA, HashAlgorithm.SHA256, "2.16.840.1.101.3.4.3.2"),
    DSA_SHA384(KeyType.DSA, HashAlgorithm.SHA384, "2.16.840.1.101.3.4.3.3"),
    DSA_SHA512(KeyType.DSA, HashAlgorithm.SHA512, "2.16.840.1.101.3.4.3.4"),

    ECDSA_NONE(KeyType.ECDSA, HashAlgorithm.NONE, "1.2.840.10045.4.3.2"),
    ECDSA_SHA1(KeyType.ECDSA, HashAlgorithm.SHA1, "1.2.840.10045.4.1"),
    ECDSA_SHA224(KeyType.ECDSA, HashAlgorithm.SHA224, "1.2.840.10045.4.3.1"),
    ECDSA_SHA256(KeyType.ECDSA, HashAlgorithm.SHA256, "1.2.840.10045.4.3.2"),
    ECDSA_SHA384(KeyType.ECDSA, HashAlgorithm.SHA384, "1.2.840.10045.4.3.3"),
    ECDSA_SHA512(KeyType.ECDSA, HashAlgorithm.SHA512, "1.2.840.10045.4.3.4");

    private final KeyType keyType;
    private final HashAlgorithm hashAlgorithm;
    private final String oid;

    SignatureAlgorithm(KeyType keyType, HashAlgorithm hashAlgorithm, String oid) {
        this.keyType = keyType;
        this.hashAlgorithm = hashAlgorithm;
        this.oid = oid;
    }

    public static SignatureAlgorithm fromKeyHashCombination(KeyType keyType, HashAlgorithm hashAlgorithm) {
        return Arrays.stream(SignatureAlgorithm.values())
                .filter(a -> a.getKeyType() == keyType && a.getHashAlgorithm() == hashAlgorithm)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Signature algorithm does not exist"));
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    public String getOid() {
        return oid;
    }
}
