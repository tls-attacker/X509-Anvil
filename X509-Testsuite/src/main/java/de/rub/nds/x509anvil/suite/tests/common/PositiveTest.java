package de.rub.nds.x509anvil.suite.tests.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.Assertions;

public class PositiveTest extends X509AnvilTest {
    @AnvilTest(id = "1")
    @ChainLength(minLength = 2, maxLength = 4, intermediateCertsModeled = 2)
<<<<<<< HEAD
    @TestStrength(2)

    public void sampleTestCase(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertValid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
            // No specific changes to config needed for this test, keeping the default valid case.
//            TODO: Test to be updated
        });
=======
    @TestStrength(1)
    @Specification(document = "None", section = "None", text = "This is a sample test case to test functionality.")
    @SeverityLevel(Severity.WARNING)
    public void sampleTestCase(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(testRunner);
        VerifierResult result = testRunner.execute(config);
        Assertions.assertTrue(result.isValid());
>>>>>>> refactor
    }

}
