/**
 * Framework - A tool for creating arbitrary certificates
 *
 * Copyright 2014-${year} Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.x509anvil.framework.x509.generator;

import de.rub.nds.asn1.Asn1Encodable;
import de.rub.nds.asn1.model.*;
import de.rub.nds.x509anvil.framework.util.PemUtil;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509Util;
import de.rub.nds.x509anvil.framework.x509.config.model.AlgorithmParametersType;
import de.rub.nds.x509anvil.framework.x509.config.model.IssuerType;
import de.rub.nds.x509anvil.framework.x509.config.model.Name;
import de.rub.nds.x509anvil.framework.x509.config.model.TimeType;
import de.rub.nds.x509attacker.x509.X509Certificate;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;
import java.io.IOException;
import java.util.Collections;

public class X509CertificateGenerator {
    private final X509CertificateConfig certificateConfig;
    private final X509CertificateConfig nextInChainConfig;

    private Asn1Sequence tbsCertificate;
    private Asn1Sequence certificateAsn1;
    private X509Certificate x509Certificate;

    public X509CertificateGenerator(X509CertificateConfig certificateConfig, X509CertificateConfig issuerConfig) {
        this.certificateConfig = certificateConfig;
        this.nextInChainConfig = issuerConfig;
    }

    public X509CertificateGenerator(X509CertificateConfig certificateConfig) {
        this.certificateConfig = certificateConfig;
        this.nextInChainConfig = null; // TODO: Check for null pointer exceptions
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

        if (certificateConfig.isSignaturePresent()) {
            Asn1PrimitiveBitString signatureField = new Asn1PrimitiveBitString();
            signatureField.setIdentifier("signatureValue");
            if (certificateConfig.isOverrideSignature()) {
                signatureField.setValue(certificateConfig.getSignaturePrivateKeyOverride());
            }
            certificateAsn1.addChild(signatureField);
        }

        // Set signature info
        SignatureInfo signatureInfo = new SignatureInfo();
        signatureInfo.setIdentifier("signatureInfo");
        signatureInfo.setType("SignatureInfo");
        signatureInfo.setToBeSignedIdentifiers(Collections.singletonList("/certificate/tbsCertificate"));
        signatureInfo.setSignatureValueTargetIdentifier("/certificate/signatureValue");
        signatureInfo.setSignatureAlgorithmOidValue(certificateConfig.getSignatureAlgorithmOid());
        try {
            signatureInfo.setParameters(certificateConfig.getSignatureAlgorithmParameters().getCopy());
        } catch (JAXBException | IOException | XMLStreamException e) {
            throw new CertificateGeneratorException("Unable to copy signature algorithm parameters from config", e);
        }

        // Set subject key info
        KeyInfo subjectKeyInfo = new KeyInfo();
        subjectKeyInfo.setIdentifier("keyInfo");
        subjectKeyInfo.setType("KeyInfo");
        try {
            subjectKeyInfo.setKeyBytes(
                PemUtil.encodeKeyAsPem(certificateConfig.getSubjectKeyPair().getPublic().getEncoded(), "PUBLIC KEY"));
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode key in PEM format", e);
        }

        // Create certificate
        x509Certificate = new X509Certificate(certificateAsn1, signatureInfo, subjectKeyInfo);

        // Sign certificate
        byte[] privateKeyForSignature;
        try {
            switch (certificateConfig.getSigner()) {
                case NEXT_IN_CHAIN:
                    if (nextInChainConfig.isStatic()) {
                        privateKeyForSignature = nextInChainConfig.getStaticX509Certificate().getKeyInfo().getKeyBytes();
                    }
                    else {
                        privateKeyForSignature = PemUtil
                                .encodeKeyAsPem(nextInChainConfig.getSubjectKeyPair().getPrivate().getEncoded(), "PRIVATE KEY");
                    }
                    break;
                case SELF:
                    privateKeyForSignature = PemUtil
                        .encodeKeyAsPem(certificateConfig.getSubjectKeyPair().getPrivate().getEncoded(), "PRIVATE KEY");
                    break;
                case OVERRIDE:
                default:
                    privateKeyForSignature = certificateConfig.getSignaturePrivateKeyOverride();
                    break;
            }
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode private key as pem", e);
        }

        KeyInfo signingKeyInfo = new KeyInfo();
        signingKeyInfo.setIdentifier("signingKeyInfo");
        signingKeyInfo.setType("KeyInfo");
        signingKeyInfo.setKeyBytes(privateKeyForSignature);

        if (certificateConfig.isSignaturePresent() && !certificateConfig.isOverrideSignature()) {
            x509Certificate.signCertificate(signingKeyInfo);
        }
    }

    public X509Certificate retrieveX509Certificate() throws CertificateGeneratorException {
        if (x509Certificate == null) {
            throw new CertificateGeneratorException("Certificate is not generated yet");
        }
        return x509Certificate;
    }

    public byte[] retrieveEncodedCertificate() throws CertificateGeneratorException {
        if (x509Certificate == null) {
            throw new CertificateGeneratorException("Certificate is not generated yet");
        }
        return x509Certificate.getEncodedCertificate();
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
        // TODO: Extensions
    }

    private void generateVersion() {
        if (certificateConfig.isVersionPresent()) {
            Asn1Explicit versionExplicitWrapper = new Asn1Explicit();
            versionExplicitWrapper.setIdentifier("explicitversion");
            versionExplicitWrapper.setOffset(0);
            Asn1Integer version = new Asn1Integer();
            version.setIdentifier("version");
            version.setValue(certificateConfig.getVersion());
            versionExplicitWrapper.addChild(version);
            tbsCertificate.addChild(versionExplicitWrapper);
        }
    }

    private void generateSerialNumber() {
        if (certificateConfig.isSerialNumberPresent()) {
            Asn1Integer serialNumber = new Asn1Integer();
            serialNumber.setIdentifier("serialNumber");
            serialNumber.setValue(certificateConfig.getSerialNumber());
            tbsCertificate.addChild(serialNumber);
        }
    }

    private void generateTbsSignature() throws CertificateGeneratorException {
        if (certificateConfig.isTbsSignaturePresent()) {
            Asn1Sequence signature = new Asn1Sequence();
            signature.setIdentifier("signature");

            Asn1ObjectIdentifier algorithm = new Asn1ObjectIdentifier();
            algorithm.setIdentifier("algorithm");
            if (certificateConfig.isOverrideTbsSignatureOid()) {
                algorithm.setValue(certificateConfig.getTbsSignatureOidOverridden());
            } else {
                algorithm.setValue(certificateConfig.getSignatureAlgorithmOid()); // TODO ????
            }
            signature.addChild(algorithm);

            if (certificateConfig.getTbsSignatureParametersType() == AlgorithmParametersType.NULL_PARAMETER) {
                Asn1Null parameters = new Asn1Null();
                parameters.setIdentifier("parameters");
                signature.addChild(parameters);
            } else if (certificateConfig.getTbsSignatureParametersType()
                == AlgorithmParametersType.PARAMETERS_PRESENT) {
                try {
                    Asn1Encodable parameters = certificateConfig.getTbsSignatureParameters().getCopy();
                    parameters.setIdentifier("parameters");
                    signature.addChild(parameters);
                } catch (JAXBException | IOException | XMLStreamException e) {
                    throw new CertificateGeneratorException(
                        "Unable to copy tbsCertificate->signature->parameters field from config", e);
                }
            }

            tbsCertificate.addChild(signature);
        }
    }

    private void generateIssuer() throws CertificateGeneratorException {
        if (certificateConfig.isIssuerPresent()) {
            Name issuer;
            switch (certificateConfig.getIssuerType()) {
                case NEXT_IN_CHAIN:
                    if (nextInChainConfig == null) {
                        throw new CertificateGeneratorException("Config of issuer certificate is null");
                    }
                    if (nextInChainConfig.isStatic()) {
                        // Copy subject field
                        try {
                            Asn1Encodable subject = X509Util.getAsn1ElementByIdentifierPath(nextInChainConfig.getStaticX509Certificate(),
                                    "tbsCertificate", "subject");
                            if (!(subject instanceof Asn1Sequence)) {
                                throw new CertificateGeneratorException("Unable to copy subject field of static certificate");
                            }
                            Asn1Encodable issuerAsn1 = subject.getCopy();
                            issuerAsn1.setIdentifier("issuer");

                            tbsCertificate.addChild(issuerAsn1);
                            return;
                        }
                        catch (IllegalArgumentException | XMLStreamException | JAXBException | IOException e) {
                            throw new CertificateGeneratorException("Unable to copy subject field of static certificate", e);
                        }
                    }
                    issuer = nextInChainConfig.getSubject();
                    break;
                case SELF:
                    issuer = certificateConfig.getSubject();
                    break;
                default: // OVERRIDE
                    issuer = certificateConfig.getIssuerOverridden();
                    break;
            }

            Asn1Sequence issuerAsn1 = issuer.getAsn1Structure("issuer");
            if (certificateConfig.getIssuerType() == IssuerType.NEXT_IN_CHAIN && nextInChainConfig.isSharedConfig()) {
                Asn1PrimitivePrintableString cn = X509Util.getCnFromName(issuerAsn1);
                // TODO create if null
                if (cn == null) {
                    throw new CertificateGeneratorException("Shared cert has no subject CN");
                }
                cn.setValue(cn.getValue() + "_" + (nextInChainConfig.getSharedId() - 1));
            }
            tbsCertificate.addChild(issuerAsn1);
        }
    }

    private void generateSubject() throws CertificateGeneratorException {
        if (certificateConfig.isSubjectPresent()) {
            Asn1Sequence subject = certificateConfig.getSubject().getAsn1Structure("subject");
            tbsCertificate.addChild(subject);
            if (certificateConfig.isSharedConfig()) {
                Asn1PrimitivePrintableString cn = X509Util.getCnFromName(subject);
                // TODO create if null
                if (cn == null) {
                    throw new CertificateGeneratorException("Shared cert has no subject CN");
                }
                cn.setValue(cn.getValue() + "_" + certificateConfig.getSharedId());
                certificateConfig.setSharedId(certificateConfig.getSharedId() + 1);
            }
        }
    }

    private void generateValidity() {
        if (certificateConfig.isValidityPresent()) {
            Asn1Sequence validity = new Asn1Sequence();
            validity.setIdentifier("validity");

            if (certificateConfig.isNotBeforePresent()) {
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
            }

            if (certificateConfig.isNotAfterPresent()) {
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
            }
            tbsCertificate.addChild(validity);
        }
    }

    private void generateSubjectPublicKeyInfo() throws CertificateGeneratorException {
        if (certificateConfig.isSubjectPublicKeyInfoPresent()) {
            // Create empty subject public key info and let X509-Attacker fill in the data
            Asn1Sequence subjectPublicKeyInfo = new Asn1Sequence();
            subjectPublicKeyInfo.setIdentifier("subjectPublicKeyInfo");
            subjectPublicKeyInfo.setType("SubjectPublicKeyInfo");
            subjectPublicKeyInfo.setAttribute("fromIdentifier", "/keyInfo");
            tbsCertificate.addChild(subjectPublicKeyInfo);
        }
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

    private void generateSignatureAlgorithm() throws CertificateGeneratorException {
        if (certificateConfig.isSignatureAlgorithmPresent()) {
            Asn1Sequence signatureAlgorithm = new Asn1Sequence();
            signatureAlgorithm.setIdentifier("signatureAlgorithm");

            // Generate signature algorithm oid
            Asn1ObjectIdentifier signatureAlgorithmOid = new Asn1ObjectIdentifier();
            if (certificateConfig.isOverrideSignatureAlgorithmOid()) {
                signatureAlgorithmOid.setValue(certificateConfig.getSignatureAlgorithmOidOverridden());
            } else {
                signatureAlgorithmOid.setValue(certificateConfig.getSignatureAlgorithmOid());
            }
            signatureAlgorithm.addChild(signatureAlgorithmOid);

            // Generate parameters
            if (certificateConfig.getSignatureAlgorithmParametersType() == AlgorithmParametersType.PARAMETERS_PRESENT) {
                try {
                    Asn1Encodable parameters = certificateConfig.getAlgorithmIdentifiersParameters().getCopy();
                    parameters.setIdentifier("parameters");
                    signatureAlgorithm.addChild(parameters);
                } catch (JAXBException | IOException | XMLStreamException e) {
                    throw new CertificateGeneratorException("Unable to copy signature algorithm parameters", e);
                }
            } else if (certificateConfig.getSignatureAlgorithmParametersType() == AlgorithmParametersType.NULL_PARAMETER) {
                Asn1Null parameters = new Asn1Null();
                parameters.setIdentifier("parameters");
                signatureAlgorithm.addChild(parameters);
            }
            certificateAsn1.addChild(signatureAlgorithm);
        }
    }
}
