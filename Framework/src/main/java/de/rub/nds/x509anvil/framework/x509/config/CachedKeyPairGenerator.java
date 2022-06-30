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
        }
        // Need to generate new key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(keySize);
        return attemptGeneratingKeyPair(keyPairGenerator, hashKey);
    }

    public static KeyPair retrieveKeyPair(String identifier, String algorithm, AlgorithmParameterSpec params)
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        String hashKey = identifier + ":" + algorithm + ":" + params;

        synchronized (keyPairCache) {
            if (keyPairCache.containsKey(hashKey)) {
                return keyPairCache.get(hashKey);
            }
        }

        // Need to generate new key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(params);
        return attemptGeneratingKeyPair(keyPairGenerator, hashKey);
    }

    private static KeyPair attemptGeneratingKeyPair(KeyPairGenerator keyPairGenerator, String hashKey) throws NoSuchAlgorithmException {
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        synchronized (keyPairCache) {
            // Did another thread create the keypair in the meantime?
            if (keyPairCache.containsKey(hashKey)) {
                return keyPairCache.get(hashKey);
            }
            keyPairCache.put(hashKey, keyPair);
        }
        return keyPair;
    }
}
