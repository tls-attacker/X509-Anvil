/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import jdk.jshell.spi.ExecutionControl;

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

    public static KeyPair retrieveKeyPair(SignatureAlgorithm algorithm, int keySize) throws NoSuchAlgorithmException {
        String hashKey = algorithm + ":" + keySize;

        synchronized (keyPairCache) {
            if (keyPairCache.containsKey(hashKey)) {
                return keyPairCache.get(hashKey);
            }
        }
        String javaName = "";
        switch (algorithm) {
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                javaName = "RSA";
                break;
            case DSA:
                javaName = "DSA";
                break;
            case ECDSA:
                javaName = "ECDSA";
                break;
            case ED25519:
            case ED448:
            case GOSTR34102001:
            case GOSTR34102012_256:
            case GOSTR34102012_512:
                throw new UnsupportedOperationException(
                    "Algorithm" + algorithm.getHumanReadable() + " not implemented.");
        }
        // Need to generate new key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(javaName);
        keyPairGenerator.initialize(keySize);
        return attemptGeneratingKeyPair(keyPairGenerator, hashKey);
    }

    public static KeyPair retrieveKeyPair(String identifier, String algorithm, AlgorithmParameterSpec params)
        throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
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

    private static KeyPair attemptGeneratingKeyPair(KeyPairGenerator keyPairGenerator, String hashKey)
        throws NoSuchAlgorithmException {
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
