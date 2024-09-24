package de.rub.nds.x509anvil.suite.tests.weakcrypto;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.ValueConstraint;
import de.rub.nds.protocol.constants.HashAlgorithm;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.suite.tests.util.TestUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class WeakHashAlgorithmTests extends X509AnvilTest {

    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", method = "allowRsa")
//    public void weakHashMd2(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
//        certificateChainConfig.getIntermediateConfig(0).amendSignatureAlgorithm(HashAlgorithm.MD2);
//        VerifierResult result = testRunner.execute(certificateChainConfig);
//        Assertions.assertFalse(result.isValid());
//    }
    public void weakHashMd2(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, config -> {
            config.amendSignatureAlgorithm(HashAlgorithm.MD2);
            VerifierResult result = testRunner.execute(config);
            return result;
        });
    }


    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", method = "allowRsa")
//    public void weakHashMd4(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
//        certificateChainConfig.getIntermediateConfig(0).amendSignatureAlgorithm(HashAlgorithm.MD4);
//        VerifierResult result = testRunner.execute(certificateChainConfig);
//        Assertions.assertFalse(result.isValid());
//    }
    public void weakHashMd4(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, config -> {
            config.amendSignatureAlgorithm(HashAlgorithm.MD4);
            VerifierResult result = testRunner.execute(config);
            return result;
        });
    }


    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @ValueConstraint(identifier = "inter0.key_type", method = "allowRsa")
//    public void weakHashMd5(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
//        certificateChainConfig.getIntermediateConfig(0).amendSignatureAlgorithm(HashAlgorithm.MD5);
//        VerifierResult result = testRunner.execute(certificateChainConfig);
//        Assertions.assertFalse(result.isValid());
//    }
    public void weakHashMd5(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, config -> {
            config.amendSignatureAlgorithm(HashAlgorithm.MD5);
            VerifierResult result = testRunner.execute(config);
            return result;
        });
    }


    @AnvilTest()
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
//    public void weakHashSha1(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
//        certificateChainConfig.getIntermediateConfig(0).amendSignatureAlgorithm(HashAlgorithm.SHA1);
//        VerifierResult result = testRunner.execute(certificateChainConfig);
//        Assertions.assertFalse(result.isValid());
//    }
    public void weakHashSha1(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(argumentsAccessor, testRunner, false, config -> {
            config.amendSignatureAlgorithm(HashAlgorithm.SHA1);
            VerifierResult result = testRunner.execute(config);
            return result;
        });
    }

}
