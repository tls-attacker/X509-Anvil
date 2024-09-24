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
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class DuplicateSubjectKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateIdenticalEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateIdenticalExtensionModifier(true, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER));
        Assertions.assertFalse(result.isValid());
         */
    }
//    public void duplicateIdenticalEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        assertInvalid(argumentsAccessor, testRunner, true, config -> {
//            VerifierResult result = testRunner.execute(config, Modifiers.duplicateIdenticalExtensionModifier(true, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER));
//            return result;
//        });
//    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateIdenticalIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateIdenticalExtensionModifier(false, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER));
        Assertions.assertFalse(result.isValid());
         */
    }
//    public void duplicateIdenticalIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        assertInvalid(argumentsAccessor, testRunner, false, config -> {
//            VerifierResult result = testRunner.execute(config, Modifiers.duplicateIdenticalExtensionModifier(false, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER));
//            return result;
//        });
//    }
//

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateDifferentEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateDifferentExtensionModifier(true,
                ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, createDuplicateExtensionValue()));
        Assertions.assertFalse(result.isValid());
         */
    }
//    public void duplicateDifferentEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        assertInvalid(argumentsAccessor, testRunner, true, config -> {
//            VerifierResult result = testRunner.execute(config, Modifiers.duplicateDifferentExtensionModifier(true, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, createDuplicateExtensionValue()));
//            return result;
//        });
//    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_subject_key_identifier_present", method = "enabled")
    public void duplicateDifferentIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
        /*
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateDifferentExtensionModifier(false,
                ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, createDuplicateExtensionValue()));
        Assertions.assertFalse(result.isValid());
         */
    }
//    public void duplicateDifferentIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        assertInvalid(argumentsAccessor, testRunner, false, config -> {
//            VerifierResult result = testRunner.execute(config, Modifiers.duplicateDifferentExtensionModifier(false, ExtensionObjectIdentifiers.SUBJECT_KEY_IDENTIFIER, createDuplicateExtensionValue()));
//            return result;
//        });
//    }


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
