/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import java.math.BigInteger;
import org.junit.platform.commons.JUnitException;

public class TestUtils {
    /**
     * Returns a supported signature algorithm oid that does not match the actually used algorithm
     */
    public static SignatureHashAlgorithmKeyLengthPair getNonMatchingAlgorithmOid(
            X509SignatureAlgorithm actualAlgorithm) {
        FeatureReport featureReport = ContextHelper.getFeatureReport();
        return featureReport.getSupportedSignatureHashAndKeyLengthPairsEntity().stream()
                .filter(a -> a.getSignatureAlgorithm() != actualAlgorithm.getSignatureAlgorithm() || a.getHashAlgorithm() != actualAlgorithm.getHashAlgorithm())
                .findFirst()
                .orElseThrow(() -> new JUnitException("No other algorithm supported"));
    }

    public static BigInteger createBigInteger(int byteLength) {
        byte[] bytes = createByteArray(byteLength);
        return new BigInteger(bytes);
    }

    public static byte[] createByteArray(int length) {
        byte[] buffer = new byte[length];
        for (int i = 0; i < length; i++) {
            buffer[i] = (byte) (i % 256);
        }
        return buffer;
    }
}
