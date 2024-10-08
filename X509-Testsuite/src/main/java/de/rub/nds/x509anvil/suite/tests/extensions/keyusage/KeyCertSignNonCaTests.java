package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class KeyCertSignNonCaTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage",
            text = "If the keyCertSign bit is asserted, then the cA bit in the basic constraints extension (Section 4.2.1.9) MUST also be asserted")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 2, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_key_cert_sign", method = "enabled")
    @ValueConstraint(identifier = "entity.ext_basic_constraints_ca", method = "disabled")
    @AnvilTest
    public void keyCertSignNonCaEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
         */
    }
}
