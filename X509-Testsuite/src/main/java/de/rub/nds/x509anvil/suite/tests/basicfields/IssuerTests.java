
package de.rub.nds.x509anvil.suite.tests.basicfields;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.asn1.model.Asn1Integer;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.RFC;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.X509CertificateModifier;
import de.rub.nds.x509attacker.x509.X509Certificate;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;
import java.util.Collections;

public class IssuerTests extends X509AnvilTest {

    @RFC(number = 5280, section = "4.1.2.4. Issuer")
    @SeverityLevel(Severity.WARNING)
    @AnvilTest(description = "The issuer field MUST contain a non-empty distinguished name (DN).")
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    public void emptyDnIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).getSubject().setRelativeDistinguishedNames(Collections.emptyList());
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
    }

    private static X509CertificateModifier createEmptyDnModifier(X509CertificateChainConfig chainConfig, boolean entity) {
        return (certificate, config, previousConfig) -> {
            // TODO Use chainpos once merged
            if (configChooser(chainConfig, config, entity)) {

            }
        };
    }

    private static boolean configChooser(X509CertificateChainConfig chainConfig, X509CertificateConfig config, boolean entity) {
        if (entity) {
            return config == chainConfig.getEntityCertificateConfig();
        } else {
            return config == chainConfig.getIntermediateConfig(0);
        }
    }
}
