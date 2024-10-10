/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.xml.Pair;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.config.extension.BasicConstraintsConfig;
import de.rub.nds.x509attacker.config.extension.ExtensionConfig;
import de.rub.nds.x509attacker.config.extension.KeyUsageConfig;
import de.rub.nds.x509attacker.constants.CertificateChainPositionType;
import de.rub.nds.x509attacker.constants.DefaultEncodingRule;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import org.junit.platform.commons.JUnitException;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class X509CertificateConfigUtil {
    public static X509CertificateConfig getDefaultCertificateConfig(boolean selfSigned,
        CertificateChainPositionType chainPosType) {
        X509CertificateConfig config = new X509CertificateConfig();
        config.setSerialNumber(generateUniqueSerialNumber());

        config.setChainPosition(chainPosType);
        config.setSelfSigned(selfSigned);

        // add all necessary extensions
        List<ExtensionConfig> extensionConfigList = new ArrayList<>();

        BasicConstraintsConfig basicConstraintsConfig = getBasicConstraintsConfig(chainPosType);
        extensionConfigList.add(basicConstraintsConfig);

        config.setExtensions(extensionConfigList);
        config.setIncludeExtensions(true);
        // TODO: decide on which extensions should be set and which not, probably clear list in attacker
        /*
         * all default values on config
         * 
         * config.setSignatureAlgorithm(X509SignatureAlgorithm.SHA256_WITH_RSA_ENCRYPTION); KeyPair keyPair =
         * generateKeyPair(SignatureAlgorithm.RSA_PKCS1, certificateName, 2048); config.applyKeyPair(keyPair);
         * config.setVersion(new BigInteger("2"));
         * 
         * 
         * config.setDefaultNotBeforeEncoding(ValidityEncoding.UTC); config.setNotBefore(DAte"220101000000Z");
         * config.setDefaultNotAfterEncoding(ValidityEncoding.UTC); config.setNotAfterValue("320101000000Z");
         * 
         * Name subject = new Name("name", NameType.SUBJECT); RelativeDistinguishedName commonNameDN = new
         * RelativeDistinguishedName("relativeDistinguishedName"); Asn1PrintableString commonName = new
         * Asn1PrintableString("commonName"); commonName.setValue(certificateName);
         * commonNameDN.addAttributeTypeAndValue(new AttributeTypeAndValue("attributeTypeAndValue",
         * X500AttributeType.COMMON_NAME, commonName.getValue().getValue()));
         * subject.addRelativeDistinguishedNames(commonNameDN); config.setSubject(subject);
         */

        return config;
    }

    public static X509CertificateConfig getDefaultCaCertificateConfig(boolean selfSigned,
        CertificateChainPositionType chainPosType) {
        X509CertificateConfig config = getDefaultCertificateConfig(selfSigned, chainPosType);

        KeyUsageConfig keyUsageConfig = new KeyUsageConfig();
        keyUsageConfig.setKeyCertSign(true);
        keyUsageConfig.setPresent(true);
        keyUsageConfig.setCritical(true);
        config.addExtensions(keyUsageConfig);

        // TODO: any extensions to set?

        /*
         * config.setExtensionsPresent(true); BasicConstraintsExtensionConfig basicConstraints =
         * (BasicConstraintsExtensionConfig) config.extension(ExtensionType.BASIC_CONSTRAINTS);
         * basicConstraints.setPresent(true); basicConstraints.setCa(true);
         * basicConstraints.setPathLenConstraintPresent(false);
         * 
         * KeyUsageExtensionConfig keyUsage = (KeyUsageExtensionConfig) config.extension(ExtensionType.KEY_USAGE);
         * keyUsage.setPresent(true); keyUsage.setKeyCertSign(true);
         * 
         * return config;
         */
        return config;
    }

    private static BasicConstraintsConfig getBasicConstraintsConfig(CertificateChainPositionType chainPosType) {
        BasicConstraintsConfig basicConstraintsConfig = new BasicConstraintsConfig();
        basicConstraintsConfig.setPresent(true);
        basicConstraintsConfig.setCritical(true);

        basicConstraintsConfig.setCa(chainPosType != CertificateChainPositionType.ENTITY);
        basicConstraintsConfig.setPathLenConstraint(5);
        basicConstraintsConfig.setIncludeCA(DefaultEncodingRule.FOLLOW_DEFAULT);
        basicConstraintsConfig.setIncludePathLenConstraint(DefaultEncodingRule.FOLLOW_DEFAULT);

        return basicConstraintsConfig;
    }

    /**
     * Returns the first extension config in the given config that matches the given extensionType. Returns null if
     * extension not found.
     */
    public static ExtensionConfig getExtensionConfig(X509CertificateConfig certificateConfig,
        X509ExtensionType extensionType) {
        return certificateConfig.getExtensions().stream()
            .filter(x -> X509ExtensionType.decodeFromOidBytes(x.getExtensionId().getEncoded()) == extensionType)
            .findFirst().orElse(null);
    }

    public static X509CertificateChainConfig createBasicConfig(int chainLength) {
        X509CertificateChainConfig x509CertificateChainConfig = new X509CertificateChainConfig();
        x509CertificateChainConfig.initializeChain(chainLength, 1);
        return x509CertificateChainConfig;
    }

    public static BigInteger generateUniqueSerialNumber() {
        UUID uuid = UUID.randomUUID();
        return new BigInteger(uuid.toString().replace("-", ""), 16);
    }

    public static void modifyAttributeAndValuePair(X509CertificateConfig config, X500AttributeType type) {
        try {
            Pair<X500AttributeType, String> cnPair =
                config.getDefaultIssuer().stream().filter(x -> x.getLeftElement() == type).findFirst().orElseThrow();
            cnPair.setRightElement(cnPair.getRightElement() + "_modified");
        } catch (NoSuchElementException e) {
            throw new JUnitException(e.getMessage());
        }
    }
}
