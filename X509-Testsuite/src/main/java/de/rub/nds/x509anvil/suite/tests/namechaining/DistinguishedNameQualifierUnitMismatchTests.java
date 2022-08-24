package de.rub.nds.x509anvil.suite.tests.namechaining;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.TestStrength;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.annotation.Specification;
import de.rub.nds.x509anvil.framework.annotation.SeverityLevel;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.constants.Severity;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.constants.AttributeTypeObjectIdentifiers;
import de.rub.nds.x509anvil.framework.x509.config.model.DirectoryStringType;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.suite.tests.util.Modifiers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class DistinguishedNameQualifierUnitMismatchTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "7.1. Internationalized Names in Distinguished Names",
            text = "Two naming attributes match if the attribute types are the same and the values of the attributes are " +
                    "an exact match after processing with the string preparation algorithm")
    @SeverityLevel(Severity.CRITICAL)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest
    public void distinguishedNameQualifierMismatch(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).getSubject().addNameComponent(AttributeTypeObjectIdentifiers.DN_QUALIFIER, "dnq", DirectoryStringType.PRINTABLE);
        VerifierResult result = testRunner.execute(chainConfig, Modifiers.nameComponentMismatchModifier(AttributeTypeObjectIdentifiers.DN_QUALIFIER));
        Assertions.assertFalse(result.isValid());
    }
}
