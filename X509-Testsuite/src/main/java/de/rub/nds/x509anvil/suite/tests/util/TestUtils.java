package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.constants.SignatureAlgorithm;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import org.junit.platform.commons.JUnitException;

import java.math.BigInteger;

public class TestUtils {
    /**
     * Returns a supported signature algorithm oid that does not match the actually used algorithm
     */
    public static String getNonMatchingAlgorithmOid(SignatureAlgorithm actualAlgorithm) {
        FeatureReport featureReport = ContextHelper.getContextDelegate().getFeatureReport();
        SignatureAlgorithm nonMatchingSignatureAlgorithm = featureReport.getSupportedAlgorithms().stream()
                .filter(a -> a != actualAlgorithm)
                .findFirst()
                .orElseThrow(() -> new JUnitException("No other algorithm supported"));
        return nonMatchingSignatureAlgorithm.getOid();
    }

    public static BigInteger create256BytesInteger() {
        byte[] bytes = new byte[256];
        for (int i = 0; i < 256; i++) {
            bytes[i] = (byte) i;
        }
        return new BigInteger(bytes);
    }
}
