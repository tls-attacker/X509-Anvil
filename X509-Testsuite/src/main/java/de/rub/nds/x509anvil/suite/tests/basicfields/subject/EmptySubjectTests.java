package de.rub.nds.x509anvil.suite.tests.basicfields.subject;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

import java.util.List;

public class EmptySubjectTests extends X509AnvilTest {
    @ChainLength(minLength = 3)
    @AnvilTest(id = "basic-e106a2171a")
    public void emptySubjectIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier) config -> config.setSubject(List.of()), testInfo);
    }
}
