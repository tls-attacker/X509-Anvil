package de.rub.nds.constants;

public class SignatureAlgorithmInfo {
    private final String oid;
    private final String name;
    private final KeyType keyType;

    public SignatureAlgorithmInfo(String oid, String name, KeyType keyType) {
        this.oid = oid;
        this.name = name;
        this.keyType = keyType;
    }

    public String getOid() {
        return oid;
    }

    public String getName() {
        return name;
    }

    public KeyType getKeyType() {
        return keyType;
    }


    public static class Rsa extends SignatureAlgorithmInfo {
        public Rsa(String oid, String name) {
            super(oid, name, KeyType.RSA);
        }
    }

    public static class Dsa extends SignatureAlgorithmInfo {
        public Dsa(String oid, String name) {
            super(oid, name, KeyType.DSA);
        }
    }

    public static class Ecdsa extends SignatureAlgorithmInfo {
        public Ecdsa(String oid, String name) {
            super(oid, name, KeyType.ECDSA);
        }
    }
}
