package de.rub.nds.x509anvil.suite.tests.extensions.subjectdirectoryattributes;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.model.Asn1PrintableString;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.SubjectDirectoryAttributesConfig;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.x509.model.AttributeValueSet;

import java.util.List;

public class CriticalSubjectDirectoryAttributesTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-ce3148df7c")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void criticalSubjectDirectoryAttributesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(true);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));
            config.addExtensions(subjectDirectoryAttributesConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-bfad73e06a")
    public void criticalSubjectDirectoryAttributesIssuer(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(true);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));
            config.addExtensions(subjectDirectoryAttributesConfig);
            config.setIncludeExtensions(true);
        });
    }
}
