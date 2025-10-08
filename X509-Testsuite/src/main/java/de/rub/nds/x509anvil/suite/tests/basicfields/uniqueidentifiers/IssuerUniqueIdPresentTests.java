package de.rub.nds.x509anvil.suite.tests.basicfields.uniqueidentifiers;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

public class IssuerUniqueIdPresentTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:version")
    @AnvilTest(id = "basic-5da143217b")
    public void issuerUniqueIdPresentInEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setIncludeIssuerUniqueId(true);
                            config.setDefaultIssuerUniqueId(new byte[] {0x0, 0x1, 0x2, 0x3});
                        });
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:version")
    @AnvilTest(id = "basic-5da113007b")
    public void issuerUniqueIdPresentInIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> {
                            config.setIncludeIssuerUniqueId(true);
                            config.setDefaultIssuerUniqueId(new byte[] {0x0, 0x1, 0x2, 0x3});
                        });
    }
}
