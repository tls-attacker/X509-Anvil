package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

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

public class CriticalAuthorityKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity:ext_authority_key_identifier_present", method = "enabled")
    public void criticalAuthorityKeyIdEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: Fix to correct config once implemented
        /* assertInvalid(testRunner, true, (X509CertificateConfigModifier )config -> {
            ExtensionConfig authorityKeyIdentifier = new UnknownConfig(X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.getOid(), "authority_key_identifier");
            authorityKeyIdentifier.setCritical(true);
            config.addExtensions(authorityKeyIdentifier);
        });

         */
    }

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0:ext_authority_key_identifier_present", method = "enabled")
    public void criticalAuthorityKeyIdIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//           TODO: Fix to correct config once implemented
     /*   assertInvalid(testRunner, false,(X509CertificateConfigModifier) config -> {
            ExtensionConfig authorityKeyIdentifier = new UnknownConfig(X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.getOid(), "authority_key_identifier");
            authorityKeyIdentifier.setCritical(true);
            config.addExtensions(authorityKeyIdentifier);
        });

      */
    }

}
