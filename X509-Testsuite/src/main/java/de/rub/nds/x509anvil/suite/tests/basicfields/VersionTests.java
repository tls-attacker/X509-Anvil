package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.CertificateChainPosType;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class VersionTests extends X509AnvilTest {

    @AnvilTest(description = "Negative test that uses a negative value for the entity's version instead of a valid version number")
    @TestStrength(2)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "entity.version")
    public void negativeVersionEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createIllegalVersionModifier(true, BigInteger.valueOf(-1)));
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "Negative test that uses a negative value for the intermediate certificate's version instead of a valid version number")
    @TestStrength(2)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter0.version")
    public void negativeVersionIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createIllegalVersionModifier(false, BigInteger.valueOf(-1)));
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "")
    @TestStrength(2)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "entity.version")
    public void invalidVersion4Entity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createIllegalVersionModifier(true, BigInteger.valueOf(3)));
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "")
    @TestStrength(2)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter0.version")
    public void invalidVersion4Intermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createIllegalVersionModifier(false, BigInteger.valueOf(3)));
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "")
    @TestStrength(2)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "entity.version")
    public void largeVersionEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createIllegalVersionModifier(true,
                new BigInteger("FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100", 16)));
        Assertions.assertFalse(result.isValid());
    }

    @AnvilTest(description = "")
    @TestStrength(2)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @IpmLimitations(identifiers = "inter0.version")
    public void largeVersionIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig certificateChainConfig = prepareConfig(argumentsAccessor, testRunner);
        VerifierResult result = testRunner.execute(certificateChainConfig, createIllegalVersionModifier(false,
                new BigInteger("FFEEDDCCBBAA99887766554433221100FFEEDDCCBBAA99887766554433221100", 17)));
        Assertions.assertFalse(result.isValid());
    }

    public static X509CertificateModifier createIllegalVersionModifier(boolean entity, BigInteger version) {
        if (entity) {
            return (certificate, config, previousConfig) -> {
                if (config.getCertificateChainPosType() == CertificateChainPosType.ENTITY) {
                    Asn1Integer versionAsn1 = (Asn1Integer) X509Util.getAsn1ElementByIdentifierPath(certificate,
                            "tbsCertificate", "explicitversion", "version");
                    versionAsn1.setValue(version);
                }
            };
        } else {
            return (certificate, config, previousConfig) -> {
                if (config.getCertificateChainPosType() == CertificateChainPosType.INTERMEDIATE) {
                    Asn1Integer versionAsn1 = (Asn1Integer) X509Util.getAsn1ElementByIdentifierPath(certificate,
                            "tbsCertificate", "explicitversion", "version");
                    versionAsn1.setValue(version);
                }
            };
        }
    }
}
