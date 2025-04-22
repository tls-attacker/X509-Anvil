package de.rub.nds.x509anvil.suite.tests.extensions.subjectkeyid;

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

public class DuplicateSubjectKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateIdenticalEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
/*        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config ->
                Modifiers.duplicateIdenticalExtensionModifier(true, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER)
        );*/
    }



    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateIdenticalIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
 /*       assertInvalid(testRunner, false, (X509CertificateConfigModifier) config ->
                Modifiers.duplicateIdenticalExtensionModifier(false, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER)
        );
        */
    }

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateDifferentEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
/*        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config ->
                Modifiers.duplicateDifferentExtensionModifier(true, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, createDuplicateExtensionValue())
        );
        */
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateDifferentIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
/*
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config ->
                Modifiers.duplicateDifferentExtensionModifier(false, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, createDuplicateExtensionValue())
        );
*/
    }


// TODO: re-implement when extension implemented in attacker
        /*
        private static byte[] createDuplicateExtensionValue() {
        Asn1OctetString subjectKeyId = new Asn1OctetString("subjectKeyId");
        subjectKeyId.setValue(TestUtils.createByteArray(20));
        Asn1FieldSerializer serializer = new Asn1FieldSerializer(subjectKeyId);
        return serializer.serialize();
    }
         */
}
