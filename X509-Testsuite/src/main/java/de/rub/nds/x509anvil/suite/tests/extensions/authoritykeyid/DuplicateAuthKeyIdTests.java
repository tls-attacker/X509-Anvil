package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class DuplicateAuthKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", method = "enabled")
    public void duplicateIdenticalEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//TODO: implement when extension is implemented
    /*      assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config -> {
            Modifiers.duplicateIdenticalExtensionModifier(true, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER);
        });

     */
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_authority_key_identifier_present", method = "enabled")
    public void duplicateIdenticalIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: implement when extension implemented in attacker
 //        assertInvalid(argumentsAccessor, testRunner, false, config -> {
//            Modifiers.duplicateIdenticalExtensionModifier(false, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER);
//        });
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", method = "enabled")
    public void duplicateDifferentEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: implement when extension implemented in attacker
 //        assertInvalid(argumentsAccessor, testRunner, true, config -> {
//            Modifiers.duplicateDifferentExtensionModifier(true, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER, createDuplicateExtensionValue());
//        });
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_authority_key_identifier_present", method = "enabled")
    public void duplicateDifferentIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: implement when extension implemented in attacker
//        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> {
//            Modifiers.duplicateDifferentExtensionModifier(false, ExtensionObjectIdentifiers.AUTHORITY_KEY_IDENTIFIER, createDuplicateExtensionValue());
//        });
    }


// TODO: implement when extension implemented in attacker
        /*
        private static byte[] createDuplicateExtensionValue() {
        AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier("auth_dupe");
        Asn1OctetString keyId = new Asn1OctetString("new_key");
        keyId.setValue(TestUtils.createByteArray(20));
        authorityKeyIdentifier.setKeyIdentifier(keyId);
        Asn1FieldSerializer serializer = new Asn1FieldSerializer(authorityKeyIdentifier);
        return serializer.serialize();
    }
         */
}
