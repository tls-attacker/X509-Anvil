package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.x509.model.Extension;
import de.rub.nds.x509attacker.x509.model.extensions.AuthorityKeyIdentifier;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class MissingKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier",
            text = "The keyIdentifier field of the authorityKeyIdentifier extension MUST be included in all certificates generated by conforming CAs.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", method = "enabled")
    public void missingKeyIdentifierEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, missingKeyIdentifierModifier());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_authority_key_identifier_present", method = "enabled")
    public void missingKeyIdentifierIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, missingKeyIdentifierModifier());
    }


    public static X509CertificateModifier missingKeyIdentifierModifier() {
        return (certificate) -> {
            Extension extension = X509Util.getExtensionByOid(certificate, X509ExtensionType.AUTHORITY_KEY_IDENTIFIER);
            Asn1OctetString extnValue = extension.getExtnValue();

            Asn1Sequence authorityKeyIdentifier = new AuthorityKeyIdentifier("missing");
            extnValue.setValue(authorityKeyIdentifier.getContent());
        };
    }
}
