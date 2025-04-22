package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;

public class InvalidCriticalExtensionTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension [...] " +
                    "that contains information that it cannot process.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 2, maxLength = 2, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.extensions_present", method = "enabled")
    @ValueConstraint(identifier = "entity.ext_subject_key_identifier_present", method = "enabled")
    @AnvilTest
    public void invalidCriticalSubjectKeyIdentifierEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
      /*  assertInvalid(testRunner, true, (X509CertificateConfigModifier)  config -> {
            //   TODO: re-implement when extension implemented in attacker
            config.extension(ExtensionType.SUBJECT_KEY_IDENTIFIER).setCritical(true);
        }, Modifiers.invalidExtensionValueModifier(true, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER));
       */
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions",
            text = "A certificate-using system MUST reject the certificate if it encounters a critical extension [...] " +
                    "that contains information that it cannot process.")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.extensions_present", method = "enabled")
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    @AnvilTest

    public void invalidCriticalSubjectKeyIdentifierIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
    /*    assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
//            TODO: re-implement when extension implemented in attacker
            config.extension(ExtensionType.SUBJECT_KEY_IDENTIFIER).setCritical(true);
        }, Modifiers.invalidExtensionValueModifier(false, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER));
    }

     */
    }
}
