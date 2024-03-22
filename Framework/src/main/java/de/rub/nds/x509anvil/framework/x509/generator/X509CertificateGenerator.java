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
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509attacker.constants.TimeContextHint;
import de.rub.nds.x509attacker.x509.model.*;

import java.io.IOException;
import java.math.BigInteger;
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
            x509Certificate.getTbsCertificate().setSubjectPublicKeyInfo();
            x509Certificate.getTbsCertificate().getSubjectPublicKeyInfo().setSubjectPublicKeyBitString(key); // TODO: set key somehow?
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode public key as pem", e);
        }

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
                    // TODO: Where is the key located now?
                    privateKeyForSignature = previousConfig.getStaticX509Certificate().getKeyInfo().getKeyBytes();
                } else {
                    privateKeyForSignature =
                        PemUtil.encodeKeyAsPem(previousConfig.getKeyPair().getPrivate().getEncoded(), "PRIVATE KEY");
                }
            }
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode private key as pem", e);
        }
        // TODO: Somehow set private key for signature?

        //TODO: Create signature?
        x509Certificate.getSignatureComputations().setToBeSignedBytes(x509Certificate.getTbsCertificate().getContent());
        x509Certificate.getSignatureComputations().setSignatureBytes(todo);//needed?

        KeyInfo signingKeyInfo = new KeyInfo();
        signingKeyInfo.setIdentifier("signingKeyInfo");
        signingKeyInfo.setType("KeyInfo");
        signingKeyInfo.setKeyBytes(privateKeyForSignature);
        x509Certificate.signCertificate(signingKeyInfo);
        // TODO: Is this needed or done automatically?
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

        // TODO no parameters, null parameter, parameters....
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
                    Asn1Encodable cn = X509Util.getCnFromName(issuer);
                    // TODO create if null
                    if (cn == null) {
                        throw new CertificateGeneratorException("Shared cert has no subject CN");
                    }
                    if (cn instanceof Asn1PrimitivePrintableString) {
                        ((Asn1PrimitivePrintableString) cn).setValue(
                            ((Asn1PrimitivePrintableString) cn).getValue() + "_" + (previousConfig.getSharedId() - 1));
                    } else if (cn instanceof Asn1PrimitiveUtf8String) {
                        ((Asn1PrimitiveUtf8String) cn).setValue(
                            ((Asn1PrimitiveUtf8String) cn).getValue() + "_" + (previousConfig.getSharedId() - 1));
                    }
                    x509Certificate.getTbsCertificate().setIssuer(issuer);
                }
            }
        }
    }

    private void setSubject() throws CertificateGeneratorException {
        Asn1Sequence subject = certificateConfig.getSubject();
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

    private void setValidity() {
        Validity validity = new Validity("validity");

        if (certificateConfig.getNotBeforeTimeType() == TimeType.UTC_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_BEFORE);
            Asn1PrimitiveUtcTime utcTime = new Asn1PrimitiveUtcTime();
            utcTime.setIdentifier("notBefore");
            utcTime.setValue(certificateConfig.getNotBeforeValue());
            time.setValue(certificateConfig.getNotBeforeValue());
            //TODO: how to select choice in time for UTC?
            validity.setNotBefore(time);
        } else if (certificateConfig.getNotBeforeTimeType() == TimeType.GENERALIZED_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_BEFORE);
            Asn1PrimitiveGeneralizedTime generalTime = new Asn1PrimitiveGeneralizedTime();
            generalTime.setIdentifier("notBefore");
            generalTime.setValue(certificateConfig.getNotBeforeValue());
            //TODO: how to select choice in time for generalized time?
            time.setValue(certificateConfig.getNotBeforeValue());
            validity.setNotBefore(time);
        }

        if (certificateConfig.getNotAfterTimeType() == TimeType.UTC_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_AFTER);
            Asn1PrimitiveUtcTime utcTime = new Asn1PrimitiveUtcTime();
            utcTime.setIdentifier("notAfter");
            utcTime.setValue(certificateConfig.getNotAfterValue());
            //TODO: how to select choice in time for UTC?
            time.setValue(certificateConfig.getNotAfterValue());
            validity.setNotAfter(time);
        } else if (certificateConfig.getNotAfterTimeType() == TimeType.GENERALIZED_TIME) {
            Time time = new Time("validity", TimeContextHint.NOT_AFTER);
            Asn1PrimitiveGeneralizedTime generalTime = new Asn1PrimitiveGeneralizedTime();
            generalTime.setIdentifier("notAfter");
            generalTime.setValue(certificateConfig.getNotAfterValue());
            //TODO: how to select choice in time for generalized time?
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

    // TODO: fix extensions
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

    private void setSignatureAlgorithm() {
        CertificateSignatureAlgorithmIdentifier algorithm = new CertificateSignatureAlgorithmIdentifier("algorithm");
        if (certificateConfig.isSelfSigned()) {
            algorithm.setContent(certificateConfig.getSignatureAlgorithmOid().getBytes());
        } else {
            algorithm.setContent(previousConfig.getSignatureAlgorithmOid().getBytes());
        }
        x509Certificate.setSignatureAlgorithmIdentifier(algorithm);
    }
}
