/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

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

/**
 * Wraps around the key Generator in the Protocol-Attacker. Caches generated keys to save runtime.
 */
public class CachedKeyPairGenerator {

    private CachedKeyPairGenerator() {}

    private static final Map<String, KeyCache> keyCaches =
        new ConcurrentHashMap<>();

    public static final long RANDOM_SEED = 123456789;
    public static final Random random = new Random(RANDOM_SEED);

    public static void generateNewKeys(SignatureHashAlgorithmKeyLengthPair algorithmLengthPair,
                                X509CertificateConfig config, String cacheIdentifier) {

        keyCaches.computeIfAbsent(cacheIdentifier, k -> new KeyCache(random));
        keyCaches.get(cacheIdentifier).generateNewKeys(algorithmLengthPair, config);
    }

    public static void generateNewKeys(SignatureHashAlgorithmKeyLengthPair algorithmLengthPair,
                                X509CertificateConfig config) {
        generateNewKeys(algorithmLengthPair, config, "DEFAULT");
    }
}
