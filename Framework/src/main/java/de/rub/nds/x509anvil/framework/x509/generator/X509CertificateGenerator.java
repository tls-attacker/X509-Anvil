/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.x509anvil.framework.util.PemUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.extension.ExtensionConfig;
import de.rub.nds.x509anvil.framework.x509.config.model.*;
import de.rub.nds.x509attacker.x509.model.X509Certificate;

import jakarta.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class X509CertificateGenerator {
    private final X509CertificateConfig certificateConfig;
    private final X509CertificateConfig previousConfig;

    private Asn1Sequence tbsCertificate;
    private Asn1Sequence certificateAsn1;
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

        generateTbsCertificate();

        certificateAsn1 = new Asn1Sequence();
        certificateAsn1.setIdentifier("certificate");
        certificateAsn1.addChild(tbsCertificate);
        generateSignatureAlgorithm();

        Asn1PrimitiveBitString signatureField = new Asn1PrimitiveBitString();
        signatureField.setIdentifier("signatureValue");
        certificateAsn1.addChild(signatureField);

        // Set signature info
        SignatureInfo signatureInfo = new SignatureInfo();
        signatureInfo.setIdentifier("signatureInfo");
        signatureInfo.setType("SignatureInfo");
        signatureInfo.setToBeSignedIdentifiers(Collections.singletonList("/certificate/tbsCertificate"));
        signatureInfo.setSignatureValueTargetIdentifier("/certificate/signatureValue");
        if (certificateConfig.isSelfSigned()) {
            signatureInfo.setSignatureAlgorithmOidValue(certificateConfig.getSignatureAlgorithmOid());
        } else {
            signatureInfo.setSignatureAlgorithmOidValue(previousConfig.getSignatureAlgorithmOid());
        }
        signatureInfo.setParameters(new Asn1Null());

        // Set subject key info
        KeyInfo subjectKeyInfo = new KeyInfo();
        subjectKeyInfo.setIdentifier("keyInfo");
        subjectKeyInfo.setType("KeyInfo");
        try {
            subjectKeyInfo.setKeyBytes(
                PemUtil.encodeKeyAsPem(certificateConfig.getKeyPair().getPublic().getEncoded(), "PUBLIC KEY"));
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode key in PEM format", e);
        }

        // Create certificate
        x509Certificate = new X509Certificate(certificateAsn1, signatureInfo, subjectKeyInfo);

        // Call certificate modifiers
        for (X509CertificateModifier certificateModifier : certificateModifiers) {
            certificateModifier.beforeSigning(x509Certificate, certificateConfig, previousConfig);
        }

        // Sign certificate
        byte[] privateKeyForSignature;
        try {
            if (certificateConfig.isSelfSigned()) {
                privateKeyForSignature =
                    PemUtil.encodeKeyAsPem(certificateConfig.getKeyPair().getPrivate().getEncoded(), "PRIVATE KEY");
            } else {
                if (previousConfig.isStatic()) {
                    privateKeyForSignature = previousConfig.getStaticX509Certificate().getKeyInfo().getKeyBytes();
                } else {
                    privateKeyForSignature =
                        PemUtil.encodeKeyAsPem(previousConfig.getKeyPair().getPrivate().getEncoded(), "PRIVATE KEY");
                }
            }
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode private key as pem", e);
        }

        KeyInfo signingKeyInfo = new KeyInfo();
        signingKeyInfo.setIdentifier("signingKeyInfo");
        signingKeyInfo.setType("KeyInfo");
        signingKeyInfo.setKeyBytes(privateKeyForSignature);
        x509Certificate.signCertificate(signingKeyInfo);
    }

    public X509Certificate retrieveX509Certificate() throws CertificateGeneratorException {
        if (x509Certificate == null) {
            throw new CertificateGeneratorException("Certificate is not generated yet");
        }
        return x509Certificate;
    }

    private void generateTbsCertificate() throws CertificateGeneratorException {
        this.tbsCertificate = new Asn1Sequence();
        tbsCertificate.setIdentifier("tbsCertificate");

        generateVersion();
        generateSerialNumber();
        generateTbsSignature();
        generateIssuer();
        generateValidity();
        generateSubject();
        generateSubjectPublicKeyInfo();
        generateUniqueIdentifiers();
        generateExtensions();
    }

    private void generateVersion() {
        // Do not encode v1 (default value)
        if (certificateConfig.getVersion() != 0) {
            Asn1Explicit versionExplicitWrapper = new Asn1Explicit();
            versionExplicitWrapper.setIdentifier("explicitversion");
            versionExplicitWrapper.setOffset(0);
            Asn1Integer version = new Asn1Integer();
            version.setIdentifier("version");
            version.setValue(BigInteger.valueOf(certificateConfig.getVersion()));
            versionExplicitWrapper.addChild(version);
            tbsCertificate.addChild(versionExplicitWrapper);
        }
    }

    private void generateSerialNumber() {
        Asn1Integer serialNumber = new Asn1Integer();
        serialNumber.setIdentifier("serialNumber");
        serialNumber.setValue(certificateConfig.getSerialNumber());
        tbsCertificate.addChild(serialNumber);
    }

    private void generateTbsSignature() throws CertificateGeneratorException {
        Asn1Sequence signature = new Asn1Sequence();
        signature.setIdentifier("signature");

        Asn1ObjectIdentifier algorithm = new Asn1ObjectIdentifier();
        algorithm.setIdentifier("algorithm");
        if (certificateConfig.isSelfSigned()) {
            algorithm.setValue(certificateConfig.getSignatureAlgorithmOid());
        } else {
            algorithm.setValue(previousConfig.getSignatureAlgorithmOid());
        }
        signature.addChild(algorithm);

        // TODO no parameters, null parameter, parameters....

        tbsCertificate.addChild(signature);
    }

    private void generateIssuer() throws CertificateGeneratorException {
        Name issuer;
        if (certificateConfig.isSelfSigned()) {
            issuer = certificateConfig.getSubject();
        } else {
            if (previousConfig.isStatic()) {
                // Copy subject field
                try {
                    Asn1Encodable subject = X509Util.getAsn1ElementByIdentifierPath(
                        previousConfig.getStaticX509Certificate(), "tbsCertificate", "subject");
                    if (!(subject instanceof Asn1Sequence)) {
                        throw new CertificateGeneratorException("Unable to copy subject field of static certificate");
                    }
                    Asn1Encodable issuerAsn1 = subject.getCopy();
                    issuerAsn1.setIdentifier("issuer");

                    tbsCertificate.addChild(issuerAsn1);
                    return;
                } catch (IllegalArgumentException | XMLStreamException | JAXBException | IOException e) {
                    throw new CertificateGeneratorException("Unable to copy subject field of static certificate", e);
                }
            } else {
                issuer = previousConfig.getSubject();
            }
        }

        Asn1Sequence issuerAsn1 = issuer.getAsn1Structure("issuer");
        if (!certificateConfig.isSelfSigned() && previousConfig.isSharedConfig()) {
            Asn1Encodable cn = X509Util.getCnFromName(issuerAsn1);
            // TODO create if null
            if (cn == null) {
                throw new CertificateGeneratorException("Shared cert has no subject CN");
            }
            if (cn instanceof Asn1PrimitivePrintableString) {
                ((Asn1PrimitivePrintableString) cn).setValue(
                    ((Asn1PrimitivePrintableString) cn).getValue() + "_" + (previousConfig.getSharedId() - 1));
            } else if (cn instanceof Asn1PrimitiveUtf8String) {
                ((Asn1PrimitiveUtf8String) cn)
                    .setValue(((Asn1PrimitiveUtf8String) cn).getValue() + "_" + (previousConfig.getSharedId() - 1));
            }
        }
        tbsCertificate.addChild(issuerAsn1);
    }

    private void generateSubject() throws CertificateGeneratorException {
        Asn1Sequence subject = certificateConfig.getSubject().getAsn1Structure("subject");
        tbsCertificate.addChild(subject);
        if (certificateConfig.isSharedConfig()) {
            Asn1Encodable cn = X509Util.getCnFromName(subject);
            // TODO create if null
            if (cn == null) {
                throw new CertificateGeneratorException("Shared cert has no subject CN");
            }
            if (cn instanceof Asn1PrimitivePrintableString) {
                ((Asn1PrimitivePrintableString) cn)
                    .setValue(((Asn1PrimitivePrintableString) cn).getValue() + "_" + certificateConfig.getSharedId());
            } else if (cn instanceof Asn1PrimitiveUtf8String) {
                ((Asn1PrimitiveUtf8String) cn)
                    .setValue(((Asn1PrimitiveUtf8String) cn).getValue() + "_" + certificateConfig.getSharedId());
            }
            certificateConfig.setSharedId(certificateConfig.getSharedId() + 1);
        }
    }

    private void generateValidity() {
        Asn1Sequence validity = new Asn1Sequence();
        validity.setIdentifier("validity");

        if (certificateConfig.getNotBeforeTimeType() == TimeType.UTC_TIME) {
            Asn1PrimitiveUtcTime utcTime = new Asn1PrimitiveUtcTime();
            utcTime.setIdentifier("notBefore");
            utcTime.setValue(certificateConfig.getNotBeforeValue());
            validity.addChild(utcTime);
        } else if (certificateConfig.getNotBeforeTimeType() == TimeType.GENERALIZED_TIME) {
            Asn1PrimitiveGeneralizedTime generalTime = new Asn1PrimitiveGeneralizedTime();
            generalTime.setIdentifier("notBefore");
            generalTime.setValue(certificateConfig.getNotBeforeValue());
            validity.addChild(generalTime);
        }

        if (certificateConfig.getNotAfterTimeType() == TimeType.UTC_TIME) {
            Asn1PrimitiveUtcTime utcTime = new Asn1PrimitiveUtcTime();
            utcTime.setIdentifier("notAfter");
            utcTime.setValue(certificateConfig.getNotAfterValue());
            validity.addChild(utcTime);
        } else if (certificateConfig.getNotAfterTimeType() == TimeType.GENERALIZED_TIME) {
            Asn1PrimitiveGeneralizedTime generalTime = new Asn1PrimitiveGeneralizedTime();
            generalTime.setIdentifier("notAfter");
            generalTime.setValue(certificateConfig.getNotAfterValue());
            validity.addChild(generalTime);
        }
        tbsCertificate.addChild(validity);
    }

    private void generateSubjectPublicKeyInfo() {
        // Create empty subject public key info and let X509-Attacker fill in the data
        Asn1Sequence subjectPublicKeyInfo = new Asn1Sequence();
        subjectPublicKeyInfo.setIdentifier("subjectPublicKeyInfo");
        subjectPublicKeyInfo.setType("SubjectPublicKeyInfo");
        subjectPublicKeyInfo.setAttribute("fromIdentifier", "/keyInfo");
        tbsCertificate.addChild(subjectPublicKeyInfo);
    }

    private void generateUniqueIdentifiers() {
        if (certificateConfig.isIssuerUniqueIdPresent()) {
            Asn1Implicit issuerUniqueIdImplicit = new Asn1Implicit();
            issuerUniqueIdImplicit.setIdentifier("implicitIssuerUniqueId");
            issuerUniqueIdImplicit.setOffset(1);

            Asn1PrimitiveBitString issuerUniqueIdBitString = new Asn1PrimitiveBitString();
            issuerUniqueIdBitString.setValue(certificateConfig.getIssuerUniqueId().getBytes());
            issuerUniqueIdBitString.setUnusedBits(certificateConfig.getIssuerUniqueId().getUnusedBits());
            issuerUniqueIdBitString.setIdentifier("issuerUniqueID");
            issuerUniqueIdImplicit.addChild(issuerUniqueIdBitString);
            tbsCertificate.addChild(issuerUniqueIdImplicit);
        }

        if (certificateConfig.isSubjectUniqueIdPresent()) {
            Asn1Implicit subjectUniqueIdImplicit = new Asn1Implicit();
            subjectUniqueIdImplicit.setIdentifier("implicitSubjectUniqueId");
            subjectUniqueIdImplicit.setOffset(2);

            Asn1PrimitiveBitString subjectUniqueIdBitString = new Asn1PrimitiveBitString();
            subjectUniqueIdBitString.setValue(certificateConfig.getSubjectUniqueId().getBytes());
            subjectUniqueIdBitString.setUnusedBits(certificateConfig.getSubjectUniqueId().getUnusedBits());
            subjectUniqueIdBitString.setIdentifier("subjectUniqueID");
            subjectUniqueIdImplicit.addChild(subjectUniqueIdBitString);
            tbsCertificate.addChild(subjectUniqueIdImplicit);
        }
    }

    private void generateExtensions() throws CertificateGeneratorException {
        Asn1Sequence extensionsAsn1 = new Asn1Sequence();
        extensionsAsn1.setIdentifier("extensions");
        for (ExtensionConfig extensionConfig : certificateConfig.getExtensions().values()) {
            if (extensionConfig.isPresent()) {
                Asn1Encodable extensionAsn1 = extensionConfig.getAsn1Structure(certificateConfig, previousConfig);
                extensionsAsn1.addChild(extensionAsn1);
            }
        }

        if (extensionsAsn1.getChildren().size() > 0 && certificateConfig.isExtensionsPresent()) {
            Asn1Explicit explicitExtensions = new Asn1Explicit();
            explicitExtensions.setIdentifier("explicitExtensions");
            explicitExtensions.setOffset(3);
            explicitExtensions.addChild(extensionsAsn1);
            tbsCertificate.addChild(explicitExtensions);
        }
    }

    private void generateSignatureAlgorithm() {
        Asn1Sequence signatureAlgorithm = new Asn1Sequence();
        signatureAlgorithm.setIdentifier("signatureAlgorithm");

        // Generate signature algorithm oid
        Asn1ObjectIdentifier signatureAlgorithmOid = new Asn1ObjectIdentifier();
        signatureAlgorithmOid.setIdentifier("algorithm");
        if (certificateConfig.isSelfSigned()) {
            signatureAlgorithmOid.setValue(certificateConfig.getSignatureAlgorithmOid());
        } else {
            signatureAlgorithmOid.setValue(previousConfig.getSignatureAlgorithmOid());
        }
        signatureAlgorithm.addChild(signatureAlgorithmOid);
        // TODO: Parameters

        certificateAsn1.addChild(signatureAlgorithm);
    }
}
