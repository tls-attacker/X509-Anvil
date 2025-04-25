package de.rub.nds.x509anvil.framework.x509.key;

import de.rub.nds.protocol.crypto.key.*;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import static de.rub.nds.x509attacker.constants.X509NamedCurve.*;
import static de.rub.nds.x509attacker.constants.X509NamedCurve.SECP384R1;

public class KeyCache {

    private final Map<SignatureHashAlgorithmKeyLengthPair, Pair<RsaPublicKey, RsaPrivateKey>> rsaKeyPairCache;
    private final Map<SignatureHashAlgorithmKeyLengthPair, DsaPublicKey> dsaPublicKeyCache;
    private final Map<SignatureHashAlgorithmKeyLengthPair, EcdsaPublicKey> ecdsaPublicKeyCache;

    private final Random random;

    KeyCache(Random random) {
        rsaKeyPairCache = new ConcurrentHashMap<>();
        dsaPublicKeyCache = new ConcurrentHashMap<>();
        ecdsaPublicKeyCache = new ConcurrentHashMap<>();
        this.random = random;
    }

    /**
     * Produces keys for the given pair of signature algorithm, hash algorithm, and key length, also updates the given
     * config with th produced key values.
     */
    public void generateNewKeys(SignatureHashAlgorithmKeyLengthPair algorithmLengthPair,
                                       X509CertificateConfig config) {

        switch (algorithmLengthPair.getSignatureAlgorithm()) {
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                Pair<RsaPublicKey, RsaPrivateKey> keyPair;
                synchronized (rsaKeyPairCache) {
                    if (rsaKeyPairCache.containsKey(algorithmLengthPair)) {
                        keyPair = rsaKeyPairCache.get(algorithmLengthPair);
                    } else {
                        keyPair = KeyGenerator.generateRsaKeys(config.getDefaultSubjectRsaPublicExponent(),
                                algorithmLengthPair.getKeyLength(), random);
                        rsaKeyPairCache.put(algorithmLengthPair, keyPair);
                    }
                }
                config.setDefaultSubjectRsaModulus(keyPair.getLeft().getModulus());
                config.setDefaultSubjectRsaPrivateExponent(keyPair.getRight().getPrivateExponent());
                break;
            case DSA:
                DsaPublicKey dsaPublicKey;
                synchronized (dsaPublicKeyCache) {
                    if (dsaPublicKeyCache.containsKey(algorithmLengthPair)) {
                        dsaPublicKey = dsaPublicKeyCache.get(algorithmLengthPair);
                    } else {
                        dsaPublicKey = KeyGenerator.generateDsaPublicKey(config.getDefaultSubjectDsaPrivateKey(),
                                algorithmLengthPair.getKeyLength(), 160, random);
                        dsaPublicKeyCache.put(algorithmLengthPair, dsaPublicKey);
                    }
                }
                config.setDefaultSubjectDsaPrimeP(dsaPublicKey.getModulus());
                config.setDefaultSubjectDsaGenerator(dsaPublicKey.getGenerator());
                config.setDefaultSubjectDsaPrimeQ(dsaPublicKey.getQ());
                config.setDefaultSubjectDsaPublicKey(dsaPublicKey.getY());
                break;
            case ECDSA:
                config.setDefaultSubjectNamedCurve(curveFromAlgorithmLengthPair(algorithmLengthPair));
                EcdsaPublicKey ecdsaPublicKey;
                synchronized (ecdsaPublicKeyCache) {
                    if (ecdsaPublicKeyCache.containsKey(algorithmLengthPair)) {
                        ecdsaPublicKey = ecdsaPublicKeyCache.get(algorithmLengthPair);
                    } else {
                        ecdsaPublicKey = KeyGenerator.generateEcdsaPublicKey(config.getDefaultSubjectEcPrivateKey(),
                                config.getDefaultSubjectNamedCurve().getParameters());
                        ecdsaPublicKeyCache.put(algorithmLengthPair, ecdsaPublicKey);
                    }
                }
                config.setDefaultSubjectEcPublicKey(ecdsaPublicKey.getPublicPoint());
                break;
        }
    }

    private static X509NamedCurve curveFromAlgorithmLengthPair(SignatureHashAlgorithmKeyLengthPair pair) {
        switch (pair.getKeyLength()) {
            // TODO: replace with constant
            case 192:
                return SECP160R1;
            case 224:
                return SECP224R1;
            case 256:
                return SECP256R1;
            case 384:
                return SECP384R1;
            default:
                throw new UnsupportedOperationException("Algorithm " + pair + " has no curve!");
        }
    }
}
