package de.rub.nds.x509anvil.suite.tests.extensions.certificatepolicies;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.asn1.oid.ObjectIdentifier;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import de.rub.nds.x509attacker.config.extension.CertificatePoliciesConfig;
import de.rub.nds.x509attacker.constants.DisplayText;
import de.rub.nds.x509attacker.constants.PolicyQualifierChoiceType;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifierInfo;
import de.rub.nds.x509attacker.x509.model.extensions.PolicyQualifiers;

import java.util.List;

public class DuplicatePoliciesTests extends X509AnvilTest {
    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:extensions_present")
    @AnvilTest(id = "extension-cb233ef8a5")
    public void duplicatePoliciesEntity(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, true, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.2", "1.3.6.1.5.5.7.2.1"));
            PolicyQualifiers userNotice = new PolicyQualifiers("userNotice");
            PolicyQualifierInfo userNoticeInfo = new PolicyQualifierInfo("userNoticeInfo");
            userNoticeInfo.setPolicyObjectIdentifier(new ObjectIdentifier("1.3.6.1.5.5.7.2.2"));
            userNoticeInfo.setQualifierChoiceType(PolicyQualifierChoiceType.USERNOTICE);
            userNoticeInfo.setIncludeNoticeRef(true);
            userNoticeInfo.setNoticeRefOrganization("testOrg");
            userNoticeInfo.setNoticeRefOrganizationType(DisplayText.IA5STRING);
            userNoticeInfo.setNoticeRefNoticeNumbers(List.of(1024L));
            userNoticeInfo.setIncludeExplicitText(true);
            userNoticeInfo.setExplicitText("Test notice text");
            userNoticeInfo.setExplicitTextType(DisplayText.IA5STRING);
            userNotice.setPolicyQualifierInfo(List.of(userNoticeInfo));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(userNotice, new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(true, false));
            config.addExtensions(certificatePoliciesConfig);
            config.setIncludeExtensions(true);
        });
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "extension-bc135fe2a1")
    public void duplicatePoliciesIntermediate(X509VerifierRunner testRunner) throws VerifierException, CertificateGeneratorException {
        assertInvalid(testRunner, false, (X509CertificateConfigModifier) config -> {
            CertificatePoliciesConfig certificatePoliciesConfig = new CertificatePoliciesConfig();
            certificatePoliciesConfig.setPresent(true);
            certificatePoliciesConfig.setCritical(true);
            certificatePoliciesConfig.setPolicyIdentifiers(List.of("1.3.6.1.5.5.7.2.1", "1.3.6.1.5.5.7.2.1"));
            certificatePoliciesConfig.setPolicyQualifiers(List.of(new PolicyQualifiers("empty"), new PolicyQualifiers("empty")));
            certificatePoliciesConfig.setIncludeQualifiers(List.of(false, false));
            config.addExtensions(certificatePoliciesConfig);
        });
    }
}
