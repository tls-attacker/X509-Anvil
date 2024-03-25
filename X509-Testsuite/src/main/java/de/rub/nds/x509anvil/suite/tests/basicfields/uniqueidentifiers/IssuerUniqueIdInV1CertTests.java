package de.rub.nds.x509anvil.suite.tests.basicfields.uniqueidentifiers;

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
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.BitString;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.suite.tests.util.Constraints;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class IssuerUniqueIdInV1CertTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.8. Unique Identifiers",
            text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.issuer_unique_id_present", method = "disabled")
    @ValueConstraint(identifier = "entity.version", method = "allowVersion1")
    @AnvilTest
    public void issuerUniqueIdPresentInV1Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setIssuerUniqueIdPresent(true);
        chainConfig.getEntityCertificateConfig().setIssuerUniqueId(new BitString(new byte[] {0x0, 0x1, 0x2, 0x3}));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "RFC 5280", section = "4.1.2.8. Unique Identifiers",
            text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.issuer_unique_id_present", method = "disabled")
    @AnvilTest
    public void issuerUniqueIdPresentInV1Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setIssuerUniqueIdPresent(true);
        chainConfig.getIntermediateConfig(0).setIssuerUniqueId(new BitString(new byte[] {0x0, 0x1, 0x2, 0x3}));
        chainConfig.getIntermediateConfig(0).setVersion(0);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
