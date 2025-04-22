package de.rub.nds.x509anvil.suite.tests.basicfields.uniqueidentifiers;

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
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;

import java.math.BigInteger;

public class IssuerUniqueIdInV1CertTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.8. Unique Identifiers",
            text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.issuer_unique_id_present", method = "disabled")
    @ValueConstraint(identifier = "entity.version", method = "allowVersion1")
    @AnvilTest
    public void issuerUniqueIdPresentInV1Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true,
                (X509CertificateConfigModifier) config -> {
                    config.setIncludeIssuerUniqueId(true);
                    config.setDefaultIssuerUniqueId(new byte[] {0x0, 0x1, 0x2, 0x3});
                });
    }


    @Specification(document = "RFC 5280", section = "4.1.2.8. Unique Identifiers",
            text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.issuer_unique_id_present", method = "disabled")
    @AnvilTest
    public void issuerUniqueIdPresentInV1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false,
                (X509CertificateConfigModifier) config -> {
                    config.setIncludeIssuerUniqueId(true);
                    config.setDefaultIssuerUniqueId(new byte[] {0x0, 0x1, 0x2, 0x3});
                    config.setVersion(BigInteger.valueOf(0));
                });
    }

}
