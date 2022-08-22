package de.rub.nds.x509anvil.suite.tests.basicfields.uniqueidentifiers;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
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

public class SubjectUniqueIdInV1CertTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.1.2.8. Unique Identifiers",
            text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.subject_unique_id_present", clazz = Constraints.class, method = "disabled")
    @ValueConstraint(identifier = "entity.version", clazz = Constraints.class, method = "allowVersion1")
    @AnvilTest
    public void subjectUniqueIdPresentInV1Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setSubjectUniqueIdPresent(true);
        chainConfig.getEntityCertificateConfig().setSubjectUniqueId(new BitString(new byte[] {0x0, 0x1, 0x2, 0x3}));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.8. Unique Identifiers",
            text = "These fields MUST only appear if the version is 2 or 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.ERROR)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.subject_unique_id_present", clazz = Constraints.class, method = "disabled")
    @AnvilTest
    public void subjectUniqueIdPresentInV1Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setSubjectUniqueIdPresent(true);
        chainConfig.getIntermediateConfig(0).setSubjectUniqueId(new BitString(new byte[] {0x0, 0x1, 0x2, 0x3}));
        chainConfig.getIntermediateConfig(0).setVersion(0);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}