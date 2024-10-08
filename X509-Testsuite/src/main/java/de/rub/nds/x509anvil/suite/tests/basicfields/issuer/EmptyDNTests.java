package de.rub.nds.x509anvil.suite.tests.basicfields.issuer;

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
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class EmptyDNTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.1.2.4. Issuer", text = "The issuer field MUST contain a non-empty distinguished name (DN).")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @AnvilTest(id = "empty_dn")

    public void emptyDn(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
<<<<<<< HEAD
//        TODO: What does "empty" actually mean?
        assertInvalid(argumentsAccessor, testRunner, false,  (X509CertificateConfigModifier) config -> {config.getSubject().clear();
            config.getSubject().add(new Pair<>(X500AttributeType.DN_QUALIFIER, "empty"));
                });
=======
        assertInvalid(argumentsAccessor, testRunner, false, (X509CertificateConfigModifier) config -> config.getSubject().clear());

        X509CertificateChainConfig chainConfig = prepareConfig(argumentsAccessor, testRunner);
        chainConfig.getIntermediateConfig(0).getSubject().clear();
        // TODO: probably not the desired outcome, what does empty DN mean?
        chainConfig.getIntermediateConfig(0).getSubject().add(new Pair<>(X500AttributeType.DN_QUALIFIER, ""));
        // chainConfig.getIntermediateConfig(0).getSubject().setRelativeDistinguishedNames(Collections.singletonList(new RelativeDistinguishedName("empty")));
        VerifierResult result = testRunner.execute(chainConfig);
        Assertions.assertFalse(result.isValid());
>>>>>>> refactor
    }

}
