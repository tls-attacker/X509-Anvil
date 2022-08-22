package de.rub.nds.x509anvil.suite.tests.extensions.common;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class V3CertWithUniqueIdsButNoExtnsTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void v3WithoutExtensionsWithSubjectUIdEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setVersion(3);
        chainConfig.getEntityCertificateConfig().setExtensionsPresent(false);
        chainConfig.getEntityCertificateConfig().setSubjectUniqueIdPresent(true);
        chainConfig.getEntityCertificateConfig().setSubjectUniqueId(new BitString(new byte[]{0,1,2,3}));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void v3WithoutExtensionsWithSubjectUIdIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setVersion(3);
        chainConfig.getIntermediateConfig(0).setExtensionsPresent(false);
        chainConfig.getIntermediateConfig(0).setSubjectUniqueIdPresent(true);
        chainConfig.getIntermediateConfig(0).setSubjectUniqueId(new BitString(new byte[]{0,1,2,3}));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void v3WithoutExtensionsWithIssuerUIdEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getEntityCertificateConfig().setVersion(3);
        chainConfig.getEntityCertificateConfig().setExtensionsPresent(false);
        chainConfig.getEntityCertificateConfig().setIssuerUniqueIdPresent(true);
        chainConfig.getEntityCertificateConfig().setIssuerUniqueId(new BitString(new byte[]{0,1,2,3}));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    @RFC(number = 5280, section = "4.1.2.9. Extensions", text = "This field MUST only appear if the version is 3 (Section 4.1.2.1).")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void v3WithoutExtensionsWithIssuerUIdIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).setVersion(3);
        chainConfig.getIntermediateConfig(0).setExtensionsPresent(false);
        chainConfig.getIntermediateConfig(0).setIssuerUniqueIdPresent(true);
        chainConfig.getIntermediateConfig(0).setIssuerUniqueId(new BitString(new byte[]{0,1,2,3}));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
