package de.rub.nds.x509anvil.suite.tests.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class PositiveTest extends X509AnvilTest {
    @AnvilTest(description = "Positive test that covers all combinations provided by our model")
    @ChainLength(minLength = 2, maxLength = 4, intermediateCertsModeled = 2)
    @TestStrength(2)
    public void sampleTestCase(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(config);
        Assertions.assertTrue(result.isValid());
    }
}
