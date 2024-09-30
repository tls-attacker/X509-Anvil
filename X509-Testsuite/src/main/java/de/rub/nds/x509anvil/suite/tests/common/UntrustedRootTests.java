package de.rub.nds.x509anvil.suite.tests.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.StaticRoot;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class UntrustedRootTests extends X509AnvilTest {

    @Specification(document = "RFC 5280")
    @AnvilTest()
    @StaticRoot(false)
    @ChainLength(minLength = 1, maxLength = 2, intermediateCertsModeled = 2)
    @TestStrength(2)
//    public void untrustedRootCertificate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
//        VerifierResult result = testRunner.execute(config);
//        Assertions.assertFalse(result.isValid());
//    }
    public void untrustedRootCertificate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
            // No specific changes to config needed, assuming root is untrusted by default for this test case.
        });
    }

}
