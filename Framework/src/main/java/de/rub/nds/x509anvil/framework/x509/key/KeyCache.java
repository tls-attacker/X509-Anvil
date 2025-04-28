/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.key;

import de.rub.nds.protocol.crypto.key.*;
import de.rub.nds.x509anvil.framework.constants.RsaKeyLength;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.X509NamedCurve;
import de.rub.nds.x509attacker.constants.X509PublicKeyType;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

import static de.rub.nds.x509attacker.constants.X509NamedCurve.*;

public class KeyCache {

    private final Map<Integer, Pair<RsaPublicKey, RsaPrivateKey>> rsaKeyPairCache;
    private final Map<Integer, DsaPublicKey> dsaPublicKeyCache;
    private final Map<Integer, EcdsaPublicKey> ecdsaPublicKeyCache;

    private final Random random;

    KeyCache(Random random) {
        rsaKeyPairCache = new ConcurrentHashMap<>();
        dsaPublicKeyCache = new ConcurrentHashMap<>();
        ecdsaPublicKeyCache = new ConcurrentHashMap<>();
        this.random = random;
    }

    /**
     * Produces keys for the given pair of signature algorithm, hash algorithm, and key length, also updates the given
     * config with the produced key values.
     */
    public void generateNewKeys(SignatureHashAlgorithmKeyLengthPair algorithmLengthPair, X509CertificateConfig config) {

        switch (algorithmLengthPair.getSignatureAlgorithm()) {
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                Pair<RsaPublicKey, RsaPrivateKey> keyPair;
                synchronized (rsaKeyPairCache) {
                    if (rsaKeyPairCache.containsKey(algorithmLengthPair.getKeyLength())) {
                        keyPair = rsaKeyPairCache.get(algorithmLengthPair.getKeyLength());
                    } else {
                        keyPair = KeyGenerator.generateRsaKeys(config.getDefaultSubjectRsaPublicExponent(),
                            algorithmLengthPair.getKeyLength(), random);
                        rsaKeyPairCache.put(algorithmLengthPair.getKeyLength(), keyPair);
                    }
                }
                config.setDefaultSubjectRsaModulus(keyPair.getLeft().getModulus());
                config.setDefaultSubjectRsaPrivateExponent(keyPair.getRight().getPrivateExponent());
                config.setPublicKeyType(X509PublicKeyType.RSA);
                break;
            case DSA:
                DsaPublicKey dsaPublicKey;
                synchronized (dsaPublicKeyCache) {
                    if (dsaPublicKeyCache.containsKey(algorithmLengthPair.getKeyLength())) {
                        dsaPublicKey = dsaPublicKeyCache.get(algorithmLengthPair.getKeyLength());
                    } else {
                        dsaPublicKey = KeyGenerator.generateDsaPublicKey(config.getDefaultSubjectDsaPrivateKey(),
                            algorithmLengthPair.getKeyLength(), 160, random);
                        dsaPublicKeyCache.put(algorithmLengthPair.getKeyLength(), dsaPublicKey);
                    }
                }
                config.setDefaultSubjectDsaPrimeP(dsaPublicKey.getModulus());
                config.setDefaultSubjectDsaGenerator(dsaPublicKey.getGenerator());
                config.setDefaultSubjectDsaPrimeQ(dsaPublicKey.getQ());
                config.setDefaultSubjectDsaPublicKey(dsaPublicKey.getY());
                config.setPublicKeyType(X509PublicKeyType.DSA);
                break;
            case ECDSA:
                config.setDefaultSubjectNamedCurve(curveFromAlgorithmLengthPair(algorithmLengthPair));
                EcdsaPublicKey ecdsaPublicKey;
                synchronized (ecdsaPublicKeyCache) {
                    if (ecdsaPublicKeyCache.containsKey(algorithmLengthPair.getKeyLength())) {
                        ecdsaPublicKey = ecdsaPublicKeyCache.get(algorithmLengthPair.getKeyLength());
                    } else {
                        ecdsaPublicKey = KeyGenerator.generateEcdsaPublicKey(config.getDefaultSubjectEcPrivateKey(),
                            config.getDefaultSubjectNamedCurve().getParameters());
                        ecdsaPublicKeyCache.put(algorithmLengthPair.getKeyLength(), ecdsaPublicKey);
                    }
                }
                config.setDefaultSubjectEcPublicKey(ecdsaPublicKey.getPublicPoint());
                config.setPublicKeyType(X509PublicKeyType.ECDH_ECDSA);
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
