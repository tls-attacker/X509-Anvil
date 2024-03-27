/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.asn1.model.*;
import de.rub.nds.asn1.parser.ParserHelper;
import de.rub.nds.protocol.constants.SignatureAlgorithm;
import de.rub.nds.protocol.crypto.key.PrivateKeyContainer;
import de.rub.nds.protocol.crypto.key.RsaPrivateKey;
import de.rub.nds.protocol.crypto.signature.SignatureCalculator;
import de.rub.nds.x509anvil.framework.constants.KeyType;
import de.rub.nds.x509anvil.framework.util.PemUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509attacker.constants.TimeContextHint;
import de.rub.nds.x509attacker.constants.X509SignatureAlgorithm;
import de.rub.nds.x509attacker.x509.model.*;
import de.rub.nds.x509attacker.x509.model.publickey.PublicKeyBitString;
import de.rub.nds.x509attacker.x509.serializer.X509Asn1FieldSerializer;
import org.apache.commons.lang3.ArrayUtils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

public class X509CertificateGenerator {
    private final X509CertificateConfig certificateConfig;
    private final X509CertificateConfig previousConfig;
    private X509Certificate x509Certificate;
    private final List<X509CertificateModifier> certificateModifiers = new ArrayList<>();

    public X509CertificateGenerator(X509CertificateConfig certificateConfig, X509CertificateConfig issuerConfig,
        List<X509CertificateModifier> certificateModifiers) {
        this.certificateConfig = certificateConfig;
        this.previousConfig = issuerConfig;
        this.certificateModifiers.addAll(certificateModifiers);
    }

    public X509CertificateGenerator(X509CertificateConfig certificateConfig, X509CertificateConfig issuerConfig) {
        this.certificateConfig = certificateConfig;
        this.previousConfig = issuerConfig;
    }

    public void addCertificateModifier(X509CertificateModifier certificateModifier) {
        certificateModifiers.add(certificateModifier);
    }

    public void generateCertificate() throws CertificateGeneratorException {
        if (certificateConfig.isStatic()) {
            this.x509Certificate = certificateConfig.getStaticX509Certificate();
            return;
        }
        this.x509Certificate = new X509Certificate("certificate"); // create basic x509 cert
        setValuesInTbsCertificate();

        setSignatureAlgorithm();

        // Set subject key info
        try {
            byte[] key = PemUtil.encodeKeyAsPem(certificateConfig.getKeyPair().getPublic().getEncoded(), "PUBLIC KEY");
            SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo("subject_key");
            PublicKeyBitString publicKeyBitString = new PublicKeyBitString("public_key");
            publicKeyBitString.setContent(key);
            subjectPublicKeyInfo.setSubjectPublicKeyBitString(publicKeyBitString);
            x509Certificate.getTbsCertificate().setSubjectPublicKeyInfo(subjectPublicKeyInfo);
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode public key as pem", e);
        }

        // Call certificate modifiers
        for (X509CertificateModifier certificateModifier : certificateModifiers) {
            certificateModifier.beforeSigning(x509Certificate, certificateConfig, previousConfig);
        }

        // Sign certificate
        RsaPrivateKey privateKeyForSignature;
        X509CertificateConfig configToConsider;
        if (certificateConfig.isSelfSigned()) {
            configToConsider = certificateConfig;
        } else {
            configToConsider = previousConfig;
        }
        // TODO: keep difference when static certificate?
        if (configToConsider.getKeyType() != KeyType.RSA) {
            throw new CertificateGeneratorException("Can only generate RSA signatures for now");
        } else {
            if (certificateConfig.isStatic()) {
                privateKeyForSignature = (RsaPrivateKey) configToConsider.getStaticCertificatePrivateKey();
            } else {
                privateKeyForSignature = (RsaPrivateKey) configToConsider.getKeyPair().getPrivate();
            }
        }


        SignatureCalculator signatureCalculator = new SignatureCalculator();

        X509SignatureAlgorithm signatureAlgorithm = x509Certificate.getX509SignatureAlgorithm();
        if (x509Certificate.getSignatureComputations() == null) {
            x509Certificate.setSignatureComputations(
                    signatureCalculator.createSignatureComputations(
                            signatureAlgorithm.getSignatureAlgorithm()));
        }

        byte[] toBeSigned = new X509Asn1FieldSerializer(x509Certificate.getTbsCertificate()).serialize();
        signatureCalculator.computeSignature(
                x509Certificate.getSignatureComputations(),
                getPrivateKeyForAlgorithm(signatureAlgorithm.getSignatureAlgorithm(), privateKeyForSignature),
                toBeSigned,
                signatureAlgorithm.getSignatureAlgorithm(),
                signatureAlgorithm.getHashAlgorithm());

        // parse to ASN.1 bit string
        ParserHelper.parseAsn1BitString(
                x509Certificate.getSignature(),
                new BufferedInputStream(
                        new ByteArrayInputStream(
                                x509Certificate.getSignatureComputations().getSignatureBytes().getValue()
                        )
                )
        );
    }

    public X509Certificate retrieveX509Certificate() throws CertificateGeneratorException {
        if (x509Certificate == null) {
            throw new CertificateGeneratorException("Certificate is not generated yet");
        }
        return x509Certificate;
    }

    private void setValuesInTbsCertificate() throws CertificateGeneratorException {
        setVersion();
        setSerialNumber();
        setSignature();
        setIssuer();
        setValidity();
        setSubject();
        setUniqueIdentifiers();
        generateExtensions();
    }

    private void setVersion() {
        // Do not encode v1 (default value)
        if (certificateConfig.getVersion() != 0) {
            Version version = new Version("version");
            version.setValue(BigInteger.valueOf(certificateConfig.getVersion()));
            this.x509Certificate.getTbsCertificate().setVersion(new X509Explicit<>("explicitversion", 0, version));
        }
    }

    private void setSerialNumber() {
        Asn1Integer serialNumber = new Asn1Integer("serialNumber");
        serialNumber.setValue(certificateConfig.getSerialNumber());
        x509Certificate.getTbsCertificate().setSerialNumber(serialNumber);
    }

    private void setSignature() throws CertificateGeneratorException {
        Asn1ObjectIdentifier algorithm = new Asn1ObjectIdentifier("algorithm");
        if (certificateConfig.isSelfSigned()) {
            algorithm.setValue(certificateConfig.getSignatureAlgorithmOid());
        } else {
            algorithm.setValue(previousConfig.getSignatureAlgorithmOid());
        }
        x509Certificate.getTbsCertificate().getSignature().setAlgorithm(algorithm);

        // TODO (old) no parameters, null parameter, parameters....
    }

    private void setIssuer() throws CertificateGeneratorException {
        Name issuer;
        if (certificateConfig.isSelfSigned()) {
            issuer = certificateConfig.getSubject();
            x509Certificate.getTbsCertificate().setIssuer(issuer);
        } else {
            if (previousConfig.isStatic()) {
                // Copy subject field
                try {
                    Name subject = previousConfig.getStaticX509Certificate().getTbsCertificate().getSubject();

                    x509Certificate.getTbsCertificate().setIssuer(subject);
                } catch (IllegalArgumentException e) {
                    throw new CertificateGeneratorException("Unable to copy subject field of static certificate", e);
                }
            } else {
                if (!certificateConfig.isSelfSigned() && previousConfig.isSharedConfig()) {
                    issuer = previousConfig.getSubject();
                    RelativeDistinguishedName cn = X509Util.getCnFromName(issuer);

                    if (cn == null) {
                        throw new CertificateGeneratorException("Shared cert has no subject CN");
                    }
                    Asn1OctetString asn1PrintableString = new Asn1OctetString("new_cn");
                    asn1PrintableString.setValue(
                        ArrayUtils.addAll(cn.getAttributeTypeAndValueList().get(0).getValue().getContent().getValue(),
                            ("_" + (previousConfig.getSharedId() - 1)).getBytes()));

                    x509Certificate.getTbsCertificate().setIssuer(issuer);
                }
            }
        }
    }

    private void setSubject() throws CertificateGeneratorException {
        Name subject = certificateConfig.getSubject();
        if (certificateConfig.isSharedConfig()) {
            RelativeDistinguishedName cn = X509Util.getCnFromName(subject);

            if (cn == null) {
                throw new CertificateGeneratorException("Shared cert has no subject CN");
            }
            Asn1OctetString asn1PrintableString = new Asn1OctetString("new_cn");
            asn1PrintableString
                .setValue(ArrayUtils.addAll(cn.getAttributeTypeAndValueList().get(0).getValue().getContent().getValue(),
                    ("_" + (previousConfig.getSharedId() - 1)).getBytes()));

            x509Certificate.getTbsCertificate().setSubject(subject);
            certificateConfig.setSharedId(certificateConfig.getSharedId() + 1);
        }
    }

    private void setValidity() {
        Validity validity = new Validity("validity");

        if (certificateConfig.getNotBeforeTimeType() == TimeType.UTC_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_BEFORE);
            Asn1PrimitiveUtcTime utcTime = new Asn1PrimitiveUtcTime();
            utcTime.setIdentifier("notBefore");
            utcTime.setValue(certificateConfig.getNotBeforeValue());
            time.setValue(certificateConfig.getNotBeforeValue());
            // TODO: how to select choice in time for UTC?
            validity.setNotBefore(time);
        } else if (certificateConfig.getNotBeforeTimeType() == TimeType.GENERALIZED_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_BEFORE);
            Asn1PrimitiveGeneralizedTime generalTime = new Asn1PrimitiveGeneralizedTime();
            generalTime.setIdentifier("notBefore");
            generalTime.setValue(certificateConfig.getNotBeforeValue());
            // TODO: how to select choice in time for generalized time?
            time.setValue(certificateConfig.getNotBeforeValue());
            validity.setNotBefore(time);
        }

        if (certificateConfig.getNotAfterTimeType() == TimeType.UTC_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_AFTER);
            Asn1PrimitiveUtcTime utcTime = new Asn1PrimitiveUtcTime();
            utcTime.setIdentifier("notAfter");
            utcTime.setValue(certificateConfig.getNotAfterValue());
            // TODO: how to select choice in time for UTC?
            time.setValue(certificateConfig.getNotAfterValue());
            validity.setNotAfter(time);
        } else if (certificateConfig.getNotAfterTimeType() == TimeType.GENERALIZED_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_AFTER);
            Asn1PrimitiveGeneralizedTime generalTime = new Asn1PrimitiveGeneralizedTime();
            generalTime.setIdentifier("notAfter");
            generalTime.setValue(certificateConfig.getNotAfterValue());
            // TODO: how to select choice in time for generalized time?
            time.setValue(certificateConfig.getNotAfterValue());
            validity.setNotAfter(time);
        }
        x509Certificate.getTbsCertificate().setValidity(validity);
    }

    private void setUniqueIdentifiers() {
        if (certificateConfig.isIssuerUniqueIdPresent()) {
            Asn1BitString issuerUniqueIdBitString = new Asn1BitString("issuerUniqueID", 1);
            issuerUniqueIdBitString.setContent(certificateConfig.getIssuerUniqueId().getBytes());
            issuerUniqueIdBitString.setUnusedBits(certificateConfig.getIssuerUniqueId().getUnusedBits());
            x509Certificate.getTbsCertificate().setIssuerUniqueId(issuerUniqueIdBitString);
        }

        if (certificateConfig.isSubjectUniqueIdPresent()) {
            Asn1BitString subjectUniqueIdBitString = new Asn1BitString("subjectUniqueID", 2);
            subjectUniqueIdBitString.setContent(certificateConfig.getSubjectUniqueId().getBytes());
            subjectUniqueIdBitString.setUnusedBits(certificateConfig.getSubjectUniqueId().getUnusedBits());
            x509Certificate.getTbsCertificate().setSubjectUniqueId(subjectUniqueIdBitString);
        }
    }

    private void generateExtensions() throws CertificateGeneratorException {
        Extensions extensions = new Extensions("extensions");
        for (ExtensionConfig extensionConfig : certificateConfig.getExtensions().values()) {
            if (extensionConfig.isPresent()) {
                Extension extension = extensionConfig.getExtensionFromConfig(certificateConfig, previousConfig);
                extensions.addExtension(extension);
            }
        }

        if (!extensions.getExtensionList().isEmpty() && certificateConfig.isExtensionsPresent()) {
            X509Explicit<Extensions> explicitExtensions = new X509Explicit<>("extensionsExplicit", 3, extensions);
            x509Certificate.getTbsCertificate().setExplicitExtensions(explicitExtensions);
        }
    }

    private void setSignatureAlgorithm() {
        CertificateSignatureAlgorithmIdentifier algorithm = new CertificateSignatureAlgorithmIdentifier("algorithm");
        if (certificateConfig.isSelfSigned()) {
            algorithm.setContent(certificateConfig.getSignatureAlgorithmOid().getBytes());
        } else {
            algorithm.setContent(previousConfig.getSignatureAlgorithmOid().getBytes());
        }
        x509Certificate.setSignatureAlgorithmIdentifier(algorithm);
    }

    private PrivateKeyContainer getPrivateKeyForAlgorithm(SignatureAlgorithm signatureAlgorithm, RsaPrivateKey privateKey) {
        switch (signatureAlgorithm) {
            case RSA_PKCS1:
            case RSA_SSA_PSS:
                return new RsaPrivateKey(
                        privateKey.getModulus(), privateKey.getPrivateExponent());
            default:
                throw new UnsupportedOperationException(
                        "The keytype \"" + signatureAlgorithm.name() + "\" is not implemented yet");
        }
    }
}
