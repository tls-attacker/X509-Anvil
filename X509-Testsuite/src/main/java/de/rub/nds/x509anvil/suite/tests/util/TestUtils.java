package de.rub.nds.x509anvil.suite.tests.util;

import de.rub.nds.x509anvil.framework.anvil.ContextHelper;
import de.rub.nds.x509anvil.framework.constants.SignatureHashAlgorithmKeyLengthPair;
import de.rub.nds.x509anvil.framework.featureextraction.FeatureReport;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import org.junit.platform.commons.JUnitException;

import java.math.BigInteger;

public class TestUtils {
    /**
     * Returns a supported signature algorithm oid that does not match the actually used algorithm
     */
    public static SignatureHashAlgorithmKeyLengthPair getNonMatchingAlgorithmOid(X509SignatureAlgorithm actualAlgorithm) {
        FeatureReport featureReport = ContextHelper.getFeatureReport();
        return featureReport.getSupportedSignatureHashAndKeyLengthPairsEntity().stream()
                .filter(a -> a.getSignatureAlgorithm() != actualAlgorithm.getSignatureAlgorithm())
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
