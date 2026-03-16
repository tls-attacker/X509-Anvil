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
import org.junit.jupiter.api.TestInfo;

import java.util.List;

public class DuplicateSubjectDirectoryAttributesTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-ca2180df7c")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void duplicateIdenticalSubjectDirectoryAttributesEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(false);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));
            config.addExtensions(subjectDirectoryAttributesConfig);
            config.addExtensions(subjectDirectoryAttributesConfig);
            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ca2181df7c")
    public void duplicateIdenticalSubjectDirectoryAttributesIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(false);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));
            config.addExtensions(subjectDirectoryAttributesConfig);
            config.addExtensions(subjectDirectoryAttributesConfig);
        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-ca2182df7c")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void duplicateDifferentSubjectDirectoryAttributesEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(false);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));
            config.addExtensions(subjectDirectoryAttributesConfig);

            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfigDifferent = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfigDifferent.setPresent(true);
            subjectDirectoryAttributesConfigDifferent.setCritical(false);
            subjectDirectoryAttributesConfigDifferent.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSetDifferent = new AttributeValueSet("attributeValueSetDifferent");
            attributeValueSetDifferent.setValues(List.of("test2"));
            attributeValueSetDifferent.setValueHolders(List.of(new Asn1PrintableString("attributeDifferent")));
            subjectDirectoryAttributesConfigDifferent.setAttributeValueSets(List.of(attributeValueSetDifferent));
            config.addExtensions(subjectDirectoryAttributesConfigDifferent);

            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ca2183df7c")
    public void duplicateDifferentSubjectDirectoryAttributesIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(false);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));
            config.addExtensions(subjectDirectoryAttributesConfig);

            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfigDifferent = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfigDifferent.setPresent(true);
            subjectDirectoryAttributesConfigDifferent.setCritical(false);
            subjectDirectoryAttributesConfigDifferent.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSetDifferent = new AttributeValueSet("attributeValueSetDifferent");
            attributeValueSetDifferent.setValues(List.of("test2"));
            attributeValueSetDifferent.setValueHolders(List.of(new Asn1PrintableString("attributeDifferent")));
            subjectDirectoryAttributesConfigDifferent.setAttributeValueSets(List.of(attributeValueSetDifferent));
            config.addExtensions(subjectDirectoryAttributesConfigDifferent);
        }, testInfo);
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "extension-ca2182df6d")
    @IpmLimitations(identifiers = "entity:extensions_present")
    public void duplicateDifferentOrderSubjectDirectoryAttributesEntity(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(false);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));

            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfigDifferent = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfigDifferent.setPresent(true);
            subjectDirectoryAttributesConfigDifferent.setCritical(false);
            subjectDirectoryAttributesConfigDifferent.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSetDifferent = new AttributeValueSet("attributeValueSetDifferent");
            attributeValueSetDifferent.setValues(List.of("test2"));
            attributeValueSetDifferent.setValueHolders(List.of(new Asn1PrintableString("attributeDifferent")));
            subjectDirectoryAttributesConfigDifferent.setAttributeValueSets(List.of(attributeValueSetDifferent));

            config.addExtensions(subjectDirectoryAttributesConfigDifferent);
            config.addExtensions(subjectDirectoryAttributesConfig);

            config.setIncludeExtensions(true);
        }, testInfo);
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-ca2183df6e")
    public void duplicateDifferentOrderSubjectDirectoryAttributesIntermediate(X509VerifierRunner testRunner, TestInfo testInfo) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfig = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfig.setPresent(true);
            subjectDirectoryAttributesConfig.setCritical(false);
            subjectDirectoryAttributesConfig.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSet = new AttributeValueSet("attributeValueSet");
            attributeValueSet.setValues(List.of("test"));
            attributeValueSet.setValueHolders(List.of(new Asn1PrintableString("attribute")));
            subjectDirectoryAttributesConfig.setAttributeValueSets(List.of(attributeValueSet));

            SubjectDirectoryAttributesConfig subjectDirectoryAttributesConfigDifferent = new SubjectDirectoryAttributesConfig();
            subjectDirectoryAttributesConfigDifferent.setPresent(true);
            subjectDirectoryAttributesConfigDifferent.setCritical(false);
            subjectDirectoryAttributesConfigDifferent.setIdentifier(List.of(X500AttributeType.COMMON_NAME.getOid().toString()));
            AttributeValueSet attributeValueSetDifferent = new AttributeValueSet("attributeValueSetDifferent");
            attributeValueSetDifferent.setValues(List.of("test2"));
            attributeValueSetDifferent.setValueHolders(List.of(new Asn1PrintableString("attributeDifferent")));
            subjectDirectoryAttributesConfigDifferent.setAttributeValueSets(List.of(attributeValueSetDifferent));

            config.addExtensions(subjectDirectoryAttributesConfigDifferent);
            config.addExtensions(subjectDirectoryAttributesConfig);
        }, testInfo);
    }
}
