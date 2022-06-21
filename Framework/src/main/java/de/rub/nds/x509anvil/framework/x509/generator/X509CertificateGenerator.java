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
import de.rub.nds.x509anvil.framework.x509.config.model.AlgorithmParametersType;
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
        signatureInfo.setKeyInfoIdentifier("keyInfo");
        signatureInfo.setSignatureAlgorithmOidValue(certificateConfig.getSignatureAlgorithmOid());
        try {
            signatureInfo.setParameters(certificateConfig.getSignatureAlgorithmParameters().getCopy());
        } catch (JAXBException | IOException | XMLStreamException e) {
            throw new CertificateGeneratorException("Unable to copy signature algorithm parameters from config", e);
        }

        // Set key info
        byte[] privateKeyForSignature;
        try {
            switch (certificateConfig.getSigner()) {
                case NEXT_IN_CHAIN:
                    privateKeyForSignature =
                        PemUtil.encodePrivateKeyAsPem(nextInChainConfig.getSubjectKeyPair().getPrivate().getEncoded());
                    break;
                case SELF:
                    privateKeyForSignature =
                        PemUtil.encodePrivateKeyAsPem(certificateConfig.getSubjectKeyPair().getPrivate().getEncoded());
                    break;
                case OVERRIDE:
                default:
                    privateKeyForSignature = certificateConfig.getSignaturePrivateKeyOverride();
                    break;
            }
        } catch (IOException e) {
            throw new CertificateGeneratorException("Unable to encode private key as pem", e);
        }

        KeyInfo keyInfo = new KeyInfo();
        keyInfo.setIdentifier("keyInfo");
        keyInfo.setType("KeyInfo");
        keyInfo.setKeyBytes(privateKeyForSignature);

        // Create and sign certificate
        x509Certificate = new X509Certificate(certificateAsn1, signatureInfo, keyInfo);

        if (certificateConfig.isSignaturePresent() && !certificateConfig.isOverrideSignature()) {
            x509Certificate.signCertificate(keyInfo);
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
        // TODO: Test if X509-Attacker supports unique identifiers at all
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
                    issuer = nextInChainConfig.getSubject();
                    break;
                case SELF:
                    issuer = certificateConfig.getSubject();
                    break;
                default: // OVERRIDE
                    issuer = certificateConfig.getIssuerOverridden();
                    break;
            }

            tbsCertificate.addChild(issuer.getAsn1Structure("issuer"));
        }
    }

    private void generateSubject() throws CertificateGeneratorException {
        if (certificateConfig.isSubjectPresent()) {
            tbsCertificate.addChild(certificateConfig.getSubject().getAsn1Structure("subject"));
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
                } else if (certificateConfig.getNotBeforeTimeType() == TimeType.GENERAL_TIME) {
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
                } else if (certificateConfig.getNotAfterTimeType() == TimeType.GENERAL_TIME) {
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
            tbsCertificate
                .addChild(certificateConfig.getSubjectPublicKeyInfo().getAsn1Structure("subjectPublicKeyInfo"));
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
            } else if (certificateConfig.getSignatureAlgorithmParametersType()
                == AlgorithmParametersType.NULL_PARAMETER) {
                Asn1Null parameters = new Asn1Null();
                parameters.setIdentifier("parameters");
                signatureAlgorithm.addChild(parameters);
            }
            certificateAsn1.addChild(signatureAlgorithm);
        }
    }

}
