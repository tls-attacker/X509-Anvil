package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1BitString;
import de.rub.nds.asn1.model.Asn1OctetString;
import de.rub.nds.asn1.serializer.Asn1FieldSerializer;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.ExtensionType;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.x509.model.Extension;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class KeyUsageOverflowTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend1Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, keyUsageOverflowModifier(true, (byte) 128, (byte) 6));
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend1Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, keyUsageOverflowModifier(false, (byte) 128, (byte) 6));
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend0Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, keyUsageOverflowModifier(true, (byte) 0, (byte) 6));
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend0Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(chainConfig, keyUsageOverflowModifier(false, (byte) 0, (byte) 6));
        Assertions.assertFalse(result.isValid());
    }

    X509CertificateModifier keyUsageOverflowModifier(boolean entity, byte bitmask, byte unusedBits) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, ExtensionObjectIdentifiers.KEY_USAGE);
                Asn1OctetString extnValue = extension.getExtnValue();

                byte[] flags = ((KeyUsageExtensionConfig) config.extension(ExtensionType.KEY_USAGE)).getFlags();
                flags[1] |= bitmask;

                Asn1BitString keyUsageAsn1 = new Asn1BitString("keyUsage");
                keyUsageAsn1.setUsedBits(flags);
                keyUsageAsn1.setUnusedBits(unusedBits);

                Asn1FieldSerializer serializer = new Asn1FieldSerializer(keyUsageAsn1);
                byte[] derEncoded = serializer.serialize();
                extnValue.setValue(derEncoded);
            }
        };
    }
}
