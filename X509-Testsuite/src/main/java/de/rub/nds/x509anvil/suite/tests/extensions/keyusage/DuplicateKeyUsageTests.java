package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.encoder.Asn1EncoderForX509;
import de.rub.nds.asn1.model.Asn1PrimitiveBitString;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.extension.KeyUsageExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import de.rub.nds.x509anvil.suite.tests.util.Modifiers;
import de.rub.nds.x509attacker.linker.Linker;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.HashMap;

public class DuplicateKeyUsageTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_key_usage_present", clazz = Constraints.class, method = "enabled")
    public void duplicateIdenticalEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateIdenticalExtensionModifier(true, ExtensionObjectIdentifiers.KEY_USAGE));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", clazz = Constraints.class, method = "enabled")
    public void duplicateIdenticalIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateIdenticalExtensionModifier(false, ExtensionObjectIdentifiers.KEY_USAGE));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_key_usage_present", clazz = Constraints.class, method = "enabled")
    public void duplicateDifferentEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateDifferentExtensionModifier(true,
                ExtensionObjectIdentifiers.KEY_USAGE, createDuplicateExtensionValue(chainConfig.getEntityCertificateConfig())));
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.2 Certificate Extensions", text = "A certificate MUST NOT include more than one instance of a particular extension")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", clazz = Constraints.class, method = "enabled")
    public void duplicateDifferentIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.duplicateDifferentExtensionModifier(false,
                ExtensionObjectIdentifiers.KEY_USAGE, createDuplicateExtensionValue(chainConfig.getIntermediateConfig(0))));
        Assertions.assertFalse(result.isValid());
    }

    private static byte[] createDuplicateExtensionValue(X509CertificateConfig chainConfig) {
        byte[] keyUsage = ((KeyUsageExtensionConfig) chainConfig.extension(ExtensionType.KEY_USAGE)).getFlags();
        byte[] val = new byte[2];
        val[0] = (byte) (~keyUsage[0] & 0xFF);
        val[1] = (byte) (~keyUsage[1] & 0xFF);

        Asn1PrimitiveBitString keyUsageAsn1 = new Asn1PrimitiveBitString();
        keyUsageAsn1.setValue(val);
        keyUsageAsn1.setUnusedBits(7);

        return Asn1EncoderForX509.encode(new Linker(new HashMap<>()), keyUsageAsn1);
    }
}