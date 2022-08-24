package de.rub.nds.x509anvil.suite.tests.encoding;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.asn1.model.Asn1Boolean;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.asn1.model.Asn1Sequence;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.constants.ExtensionObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class BerInsteadOfDerTests extends X509AnvilTest {

    @Specification(document = "X.690", section = "11.1 Boolean values ",
            text = "If the encoding represents the boolean value TRUE, its single contents octet shall have all eight bits set to one")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_critical", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "Encode a TRUE value using a value 0 < value < 0xFF")
    public void booleanRepresentationEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(config, nonFFTrueBooleanModifier(true));
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "X.690", section = "11.1 Boolean values ",
            text = "If the encoding represents the boolean value TRUE, its single contents octet shall have all eight bits set to one")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_critical", clazz = Constraints.class, method = "enabled")
    @AnvilTest(description = "Encode a TRUE value using a value 0 < value < 0xFF")
    public void booleanRepresentationIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(config, nonFFTrueBooleanModifier(false));
        Assertions.assertFalse(result.isValid());
    }


    @Specification(document = "X.690", section = "11.5 Set and sequence components with default value",
            text = "The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.version", clazz = Constraints.class, method = "allowVersion1")
    @AnvilTest(description = "Explicitly encode version 1 field")
    public void explicitVersion1Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        config.getEntityCertificateConfig().setVersion(2);  // Set version to 3 to make modification easier
        VerifierResult result = testRunner.execute(config, explicitVersion1Modifier(true));
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "X.690", section = "11.5 Set and sequence components with default value",
            text = "The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.version", clazz = Constraints.class, method = "allowVersion1")
    @AnvilTest(description = "Explicitly encode version 1 field")
    public void explicitVersion1Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        config.getIntermediateConfig(0).setVersion(2);  // Set version to 3 to make modification easier
        VerifierResult result = testRunner.execute(config, explicitVersion1Modifier(false));
        Assertions.assertFalse(result.isValid());
    }


    private static X509CertificateModifier nonFFTrueBooleanModifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Sequence keyUsageExtension = X509Util.getExtensionByOid(certificate, ExtensionObjectIdentifiers.KEY_USAGE);
                Asn1Boolean critical = (Asn1Boolean) keyUsageExtension.getChildren().get(1);
                critical.setContent(new byte[]{0x01});
            }
        };
    }

    private static X509CertificateModifier explicitVersion1Modifier(boolean entity) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Asn1Integer version = (Asn1Integer) X509Util.getAsn1ElementByIdentifierPath(certificate,
                        "tbsCertificate", "explicitversion", "version");
                version.setValue(BigInteger.valueOf(0));
            }
        };
    }
}
