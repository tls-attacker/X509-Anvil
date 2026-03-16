package de.rub.nds.x509anvil.suite.tests.basicfields.version;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

public class NoVersionTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "basic-a5a68afea1")
    @IpmLimitations(identifiers = "entity:version")
    public void noVersionEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier) config -> config.setIncludeVersion(false), testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-a6b1964ba3")
    @IpmLimitations(identifiers = "inter0:version")
    public void noVersionIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> config.setIncludeVersion(false), testInfo);
    }
}
