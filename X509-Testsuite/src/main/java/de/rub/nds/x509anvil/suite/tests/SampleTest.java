package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.x509anvil.framework.junit.execution.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.junit.test.GenericX509VerifierTest;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class SampleTest extends GenericX509VerifierTest {
    public void sampleTestCase(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(config);
        Assertions.assertTrue(result.isValid());
    }
}
