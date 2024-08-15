package de.rub.nds.x509anvil.suite.tests.encoding;

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
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateChainGenerator;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.constants.X509Version;
import de.rub.nds.x509attacker.x509.model.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.util.List;

public class BerInsteadOfDerTests extends X509AnvilTest {

    @Specification(document = "X.690", section = "11.1 Boolean values ",
            text = "If the encoding represents the boolean value TRUE, its single contents octet shall have all eight bits set to one")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_critical", method = "enabled")
    @AnvilTest()
    public void booleanRepresentationEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        X509Util.getExtensionByOid(generatedCertificates.get(generatedCertificates.size()-1), X509ExtensionType.KEY_USAGE).getCritical().setContent(new byte[] {0x01});
        VerifierResult result = testRunner.execute(generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "X.690", section = "11.1 Boolean values ",
            text = "If the encoding represents the boolean value TRUE, its single contents octet shall have all eight bits set to one")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_critical", method = "enabled")
    @AnvilTest()
    public void booleanRepresentationIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        X509CertificateChainGenerator certificateChainGenerator = new X509CertificateChainGenerator(config);
        certificateChainGenerator.generateCertificateChain();
        List<X509Certificate> generatedCertificates = certificateChainGenerator.retrieveCertificateChain();
        X509Util.getExtensionByOid(generatedCertificates.get(generatedCertificates.size()-2), X509ExtensionType.KEY_USAGE).getCritical().setContent(new byte[] {0x01});
        VerifierResult result = testRunner.execute(generatedCertificates);
        Assertions.assertFalse(result.isValid());
    }


    @Specification(document = "X.690", section = "11.5 Set and sequence components with default value",
            text = "The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.version", method = "allowVersion1")
    @AnvilTest()
    public void explicitVersion1Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        config.getEntityCertificateConfig().setVersion(X509Version.V1.getValue());
        VerifierResult result = testRunner.execute(config);
        Assertions.assertFalse(result.isValid());
    }

    @Specification(document = "X.690", section = "11.5 Set and sequence components with default value",
            text = "The encoding of a set value or sequence value shall not include an encoding for any component value which is equal to its default value.")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.version", method = "allowVersion1")
    @AnvilTest()
    public void explicitVersion1Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig config = prepareConfig(argumentsAccessor, testRunner);
        config.getIntermediateConfig(0).setVersion(X509Version.V1.getValue());
        VerifierResult result = testRunner.execute(config);
        Assertions.assertFalse(result.isValid());
    }
}
