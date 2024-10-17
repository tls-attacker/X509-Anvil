package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

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
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class DuplicateKeyUsageTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_key_usage_present", method = "enabled")
    public void duplicateIdenticalEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//     TODO: re-implement when extension implemented in attacker

/*     assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config ->
            Modifiers.duplicateIdenticalExtensionModifier(true, ExtensionObjectIdentifiers.KEY_USAGE)
            );
            */

    }

    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    public void duplicateIdenticalIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker

 /*       assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config ->
                Modifiers.duplicateIdenticalExtensionModifier(false, ExtensionObjectIdentifiers.KEY_USAGE)
        );
        */
    }



    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_key_usage_present", method = "enabled")
    public void duplicateDifferentEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker

/*        assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier) config ->
                Modifiers.duplicateDifferentExtensionModifier(true,
                        ExtensionObjectIdentifiers.KEY_USAGE, createDuplicateExtensionValue(config))
        );*/
    }


    @Specification(document = "RFC 5280", section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    public void duplicateDifferentIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker

/*        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateModifier) config ->
                Modifiers.duplicateDifferentExtensionModifier(false,
                        ExtensionObjectIdentifiers.KEY_USAGE, createDuplicateExtensionValue(config))
        );*/
    }


    // TODO: re-implement when extension implemented in attacker
        /*

    private static byte[] createDuplicateExtensionValue(X509CertificateConfig chainConfig) {
        byte[] keyUsage = ((KeyUsageExtensionConfig) chainConfig.extension(ExtensionType.KEY_USAGE)).getFlags();
        byte[] val = new byte[2];
        val[0] = (byte) (~keyUsage[0] & 0xFF);
        val[1] = (byte) (~keyUsage[1] & 0xFF);

        Asn1BitString keyUsageAsn1 = new Asn1BitString("keyUsage");
        keyUsageAsn1.setUsedBits(val);
        keyUsageAsn1.setUnusedBits((byte) 7);

        Asn1FieldSerializer serializer = new Asn1FieldSerializer(keyUsageAsn1);
        return serializer.serialize();
    }
         */
}
