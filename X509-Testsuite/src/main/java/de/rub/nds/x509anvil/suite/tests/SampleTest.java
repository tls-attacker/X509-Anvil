package de.rub.nds.x509anvil.suite.tests;

import de.rub.nds.x509anvil.framework.annotations.CombinatorialX509Test;
import de.rub.nds.x509anvil.framework.junit.execution.X509TestRunner;
import de.rub.nds.x509anvil.framework.junit.test.GenericX509VerifierTest;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class SampleTest extends GenericX509VerifierTest {
    @CombinatorialX509Test(description = "A description")
    public void sampleTestCase(ArgumentsAccessor argumentsAccessor, X509TestRunner testRunner) {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        System.out.println("Test");
    }
}
