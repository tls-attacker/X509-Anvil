package de.rub.nds.x509anvil.suite.tests.extensions.authoritykeyid;

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
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.config.extension.UnknownConfig;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

import java.math.BigInteger;

public class CriticalAuthorityKeyIdTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 2, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "entity.ext_authority_key_identifier_present", method = "enabled")

    public void criticalAuthorityKeyIdEntity(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: Fix to correct config once implemented
        /* assertInvalid(argumentsAccessor, testRunner, true, (X509CertificateConfigModifier )config -> {
            ExtensionConfig authorityKeyIdentifier = new UnknownConfig(X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.getOid(), "authority_key_identifier");
            authorityKeyIdentifier.setCritical(true);
            config.addExtensions(authorityKeyIdentifier);
        });

         */
    }

    @Specification(document = "RFC 5280", section = "4.2.1.1. Authority Key Identifier", text = "Conforming CAs MUST mark this extension as non-critical.")
    @SeverityLevel(Severity.INFORMATIONAL)
    @ChainLength(minLength = 3, maxLength = 3)
    @TestStrength(2)
    @AnvilTest
    @ValueConstraint(identifier = "inter0.ext_authority_key_identifier_present", method = "enabled")

    public void criticalAuthorityKeyIdIntermediate(ArgumentsAccessor argumentsAccessor, X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
//           TODO: Fix to correct config once implemented
     /*   assertInvalid(argumentsAccessor, testRunner, false,(X509CertificateConfigModifier) config -> {
            ExtensionConfig authorityKeyIdentifier = new UnknownConfig(X509ExtensionType.AUTHORITY_KEY_IDENTIFIER.getOid(), "authority_key_identifier");
            authorityKeyIdentifier.setCritical(true);
            config.addExtensions(authorityKeyIdentifier);
        });

      */
    }

}
