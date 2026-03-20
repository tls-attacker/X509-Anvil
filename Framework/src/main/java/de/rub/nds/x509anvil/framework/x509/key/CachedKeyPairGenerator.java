/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.key;

import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Wraps around the key Generator in the Protocol-Attacker. Caches generated keys to save runtime.
 */
public class CachedKeyPairGenerator {

    /** Prevent instantiation of this class. */
    private CachedKeyPairGenerator() {}

    private static final Map<String, KeyCache> keyCaches = new ConcurrentHashMap<>();

    public static final long RANDOM_SEED = 123456789;
    public static final Random random = new Random(RANDOM_SEED);

    public static void generateNewKeys(
            SignatureHashAlgorithmKeyLengthPair algorithmLengthPair,
            X509CertificateConfig config,
            String cacheIdentifier) {

        keyCaches.computeIfAbsent(cacheIdentifier, k -> new KeyCache(random));
        keyCaches.get(cacheIdentifier).generateNewKeys(algorithmLengthPair, config, cacheIdentifier);
    }
}
