package de.rub.nds.x509anvil.framework.x509.config;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Since generating fresh key pairs for every test case is really inefficient, we store and reuse key pairs.
 */
public class CachedKeyPairGenerator {
    private static final Map<String, KeyPair> keyPairCache = new ConcurrentHashMap<>();

    public static KeyPair retrieveKeyPair(String identifier, String algorithm, int keySize) throws NoSuchAlgorithmException {
        String hashKey = identifier + ":" + algorithm + ":" + keySize;

        synchronized (keyPairCache) {
            if (keyPairCache.containsKey(hashKey)) {
                return keyPairCache.get(hashKey);
            }
            else {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
                keyPairGenerator.initialize(keySize);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                keyPairCache.put(hashKey, keyPair);
                return keyPair;
            }
        }
    }

    public static KeyPair retrieveKeyPair(String identifier, String algorithm, AlgorithmParameterSpec params)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        String hashKey = identifier + ":" + algorithm + ":" + params;

        synchronized (keyPairCache) {
            if (keyPairCache.containsKey(hashKey)) {
                return keyPairCache.get(hashKey);
            }
            else {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
                keyPairGenerator.initialize(params);

                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                keyPairCache.put(hashKey, keyPair);
                return keyPair;
            }
        }
    }
}
