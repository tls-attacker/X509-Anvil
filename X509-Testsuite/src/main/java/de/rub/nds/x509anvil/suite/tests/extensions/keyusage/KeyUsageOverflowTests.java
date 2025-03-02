package de.rub.nds.x509anvil.suite.tests.extensions.keyusage;

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
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;

public class KeyUsageOverflowTests extends X509AnvilTest {

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend1Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
/*         assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            keyUsageOverflowModifier(true, (byte) 128, (byte) 6);
        });
*/
    }


    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend1Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker
/*

        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            keyUsageOverflowModifier(false, (byte) 128, (byte) 6);
        });
*/
    }

    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 2, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "entity.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend0Entity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker

/*        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            keyUsageOverflowModifier(true, (byte) 0, (byte) 6);
        });
        */
    }


    @Specification(document = "RFC 5280", section = "4.2.1.3. Key Usage")
    @SeverityLevel(Severity.WARNING)
    @ChainLength(minLength = 3, maxLength = 3, intermediateCertsModeled = 2)
    @TestStrength(2)
    @ValueConstraint(identifier = "inter0.ext_key_usage_present", method = "enabled")
    @AnvilTest()
    public void keyUsageOverflowAppend0Intermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        // TODO: re-implement when extension implemented in attacker

/*        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            keyUsageOverflowModifier(false, (byte) 0, (byte) 6);
        });
        */
    }


    // TODO: re-implement when extension implemented in attacker
        /*
    X509CertificateModifier keyUsageOverflowModifier(boolean entity, byte bitmask, byte unusedBits) {
        return (certificate, config, previousConfig) -> {
            if (entity && config.isEntity() || !entity && config.isIntermediate()) {
                Extension extension = X509Util.getExtensionByOid(certificate, ExtensionObjectIdentifiers.KEY_USAGE);
                Asn1OctetString extnValue = extension.getExtnValue();

                byte[] flags = ((KeyUsageExtensionConfig) config.extension(ExtensionType.KEY_USAGE)).getFlags();
                flags[1] |= bitmask;

                Asn1BitString keyUsageAsn1 = new Asn1BitString("keyUsage");
                keyUsageAsn1.setUsedBits(flags);
                keyUsageAsn1.setUnusedBits(unusedBits);

                Asn1FieldSerializer serializer = new Asn1FieldSerializer(keyUsageAsn1);
                byte[] derEncoded = serializer.serialize();
                extnValue.setValue(derEncoded);
            }
        };
    }
         */
}
