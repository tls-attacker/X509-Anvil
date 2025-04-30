package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import java.util.List;
import org.junit.jupiter.api.Assertions;

public class DistinguishedNameQualifierUnitMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two naming attributes match if the attribute types are the same and the values of the attributes are " +
                    "an exact match after processing with the string preparation algorithm")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void distinguishedNameQualifierMismatch(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        //TODO: new assert and preparator incorrect
        X509CertificateChainConfig chainConfig = prepareConfig(testRunner);
        chainConfig.getLastSigningConfig().setSubject(List.of(new Pair<>(X500AttributeType.DN_QUALIFIER, "dnq"))); //
        chainConfig.getEntityCertificateConfig().getDefaultIssuer().add(new Pair<>(X500AttributeType.DN_QUALIFIER, "dnq")); //
        X509CertificateConfigUtil.modifyAttributeAndValuePairInSubject(chainConfig.getEntityCertificateConfig(), X500AttributeType.DN_QUALIFIER);
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }
}
