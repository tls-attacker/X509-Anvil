/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.generator;

// TODO: I hope we can delete all of this when generating certificates with the attacker config, preparator, and serializer...

/*
 * public class X509CertificateGenerator { private final X509CertificateConfig certificateConfig; private final
 * X509CertificateConfig previousConfig; private X509Certificate x509Certificate; private final
 * List<X509CertificateModifier> certificateModifiers = new ArrayList<>();
 * 
 * public X509CertificateGenerator(X509CertificateConfig certificateConfig, X509CertificateConfig issuerConfig,
 * List<X509CertificateModifier> certificateModifiers) { this.certificateConfig = certificateConfig; this.previousConfig
 * = issuerConfig; this.certificateModifiers.addAll(certificateModifiers); }
 * 
 * public X509CertificateGenerator(X509CertificateConfig certificateConfig, X509CertificateConfig issuerConfig) {
 * this.certificateConfig = certificateConfig; this.previousConfig = issuerConfig; }
 * 
 * public void addCertificateModifier(X509CertificateModifier certificateModifier) {
 * certificateModifiers.add(certificateModifier); }
 * 
 * public X509Certificate generateCertificate() throws CertificateGeneratorException { if (certificateConfig.isStatic())
 * { this.x509Certificate = certificateConfig.getStaticX509Certificate(); return this.x509Certificate; }
 * 
 * // TODO: probably replace everything from here with config and serializer this.x509Certificate = new
 * X509Certificate("certificate"); // create basic x509 cert setValuesInTbsCertificate();
 * 
 * setSignatureAlgorithm();
 * 
 * // Set subject key info SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo("subject_key");
 * PublicKeyBitString publicKeyBitString = new PublicKeyBitString("public_key");
 * publicKeyBitString.setX509PublicKeyContent(certificateConfig.getPublicKey());
 * subjectPublicKeyInfo.setSubjectPublicKeyBitString(publicKeyBitString);
 * x509Certificate.getTbsCertificate().setSubjectPublicKeyInfo(subjectPublicKeyInfo);
 * 
 * // Call certificate modifiers for (X509CertificateModifier certificateModifier : certificateModifiers) {
 * certificateModifier.beforeSigning(x509Certificate, certificateConfig, previousConfig); }
 * 
 * // Sign certificate PrivateKeyContainer privateKeyForSignature; X509CertificateConfig configToConsider; if
 * (certificateConfig.isSelfSigned()) { configToConsider = certificateConfig; } else { configToConsider =
 * previousConfig; }
 * 
 * // TODO: keep difference when static certificate?
 * 
 * // if (configToConsider.getKeyType() != KeyType.RSA && !configToConsider.isStatic()) { throw new //
 * CertificateGeneratorException("Can only generate RSA signatures for now"); } else { privateKeyForSignature = //
 * (RsaPrivateKey) configToConsider.getStaticCertificatePrivateKey(); }
 * 
 * 
 * privateKeyForSignature = configToConsider.getStaticCertificatePrivateKey(); SignatureCalculator signatureCalculator =
 * new SignatureCalculator();
 * 
 * X509SignatureAlgorithm signatureAlgorithm = configToConsider.getSignatureAlgorithm(); if
 * (x509Certificate.getSignatureComputations() == null) { x509Certificate.setSignatureComputations(
 * signatureCalculator.createSignatureComputations(signatureAlgorithm.getSignatureAlgorithm())); }
 * 
 * X509CertificateConfig config = new X509CertificateConfig(); config.setVersion(x509Certificate.getX509Version());
 * 
 * // TODO: Chooser? // config.setDefaultNotAfterEncoding(ValidityEncoding.GENERALIZED_TIME_UTC); //
 * config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC); // config.setNotAfter();
 * 
 * // TODO: add extensions
 * 
 * x509Certificate.getTbsCertificate().setExplicitExtensions(null);
 * 
 * // Set Validity Time Types switch (certificateConfig.getNotBeforeTimeType()) { case UTC_TIME:
 * config.setDefaultNotBeforeEncoding(ValidityEncoding.UTC); break; case GENERALIZED_TIME:
 * config.setDefaultNotBeforeEncoding(ValidityEncoding.GENERALIZED_TIME_UTC); break; } switch
 * (certificateConfig.getNotAfterTimeType()) { case UTC_TIME: config.setDefaultNotAfterEncoding(ValidityEncoding.UTC);
 * break; case GENERALIZED_TIME: config.setDefaultNotAfterEncoding(ValidityEncoding.GENERALIZED_TIME_UTC); break; } //
 * config.setIncludeExtensions(true); x509Certificate.getTbsCertificate().getPreparator(new X509Chooser(config, new
 * X509Context())).prepare(); byte[] toBeSigned = x509Certificate.getTbsCertificate().getSerializer(new
 * X509Chooser(config, new X509Context())).serialize();
 * signatureCalculator.computeSignature(x509Certificate.getSignatureComputations(), privateKeyForSignature, toBeSigned,
 * signatureAlgorithm.getSignatureAlgorithm(), signatureAlgorithm.getHashAlgorithm()); // override values set by
 * preparator x509Certificate.getSignature().setUsedBits(
 * ModifiableVariableFactory.safelySetValue(x509Certificate.getSignature().getUsedBits(), new byte[] {}));
 * x509Certificate.getSignature().getUsedBits().setModification(new ByteArrayExplicitValueModification(
 * x509Certificate.getSignatureComputations().getSignatureBytes().getValue()));
 * 
 * return x509Certificate; }
 * 
 * private void setValuesInTbsCertificate() throws CertificateGeneratorException { setVersion(); setSerialNumber();
 * setSignature(); setIssuer(); setValidity(); setSubject(); setUniqueIdentifiers(); // TODO: implement extensions in
 * x509-attacker generateExtensions(); }
 * 
 * private void setVersion() { Version version = new Version("version");
 * version.setValue(BigInteger.valueOf(certificateConfig.getVersion()));
 * this.x509Certificate.getTbsCertificate().setVersion(new X509Explicit<>("explicitversion", 0, version)); }
 * 
 * private void setSerialNumber() { Asn1Integer serialNumber = new Asn1Integer("serialNumber");
 * serialNumber.setValue(certificateConfig.getSerialNumber());
 * x509Certificate.getTbsCertificate().setSerialNumber(serialNumber); }
 * 
 * private void setSignature() throws CertificateGeneratorException { Asn1ObjectIdentifier algorithm = new
 * Asn1ObjectIdentifier("algorithm"); if (certificateConfig.isSelfSigned()) {
 * algorithm.setValue(certificateConfig.getSignatureAlgorithmOid()); } else {
 * algorithm.setValue(previousConfig.getSignatureAlgorithmOid()); }
 * x509Certificate.getTbsCertificate().getSignature().setAlgorithm(algorithm);
 * 
 * // TODO (old) no parameters, null parameter, parameters.... }
 * 
 * private void setIssuer() throws CertificateGeneratorException { Name issuer; if (certificateConfig.isSelfSigned()) {
 * issuer = certificateConfig.getSubject(); x509Certificate.getTbsCertificate().setIssuer(issuer); } else { if
 * (previousConfig.isStatic()) { // Copy subject field try { Name subject =
 * previousConfig.getStaticX509Certificate().getTbsCertificate().getSubject();
 * 
 * x509Certificate.getTbsCertificate().setIssuer(subject); } catch (IllegalArgumentException e) { throw new
 * CertificateGeneratorException("Unable to copy subject field of static certificate", e); } } else { if
 * (!certificateConfig.isSelfSigned() && previousConfig.isSharedConfig()) { issuer = previousConfig.getSubject();
 * RelativeDistinguishedName cn = X509Util.getCnFromName(issuer);
 * 
 * if (cn == null) { throw new CertificateGeneratorException("Shared cert has no subject CN"); } Asn1OctetString
 * asn1PrintableString = new Asn1OctetString("new_cn"); asn1PrintableString.setValue(
 * ArrayUtils.addAll(cn.getAttributeTypeAndValueList().get(0).getValue().getContent().getValue(), ("_" +
 * (previousConfig.getSharedId() - 1)).getBytes()));
 * 
 * x509Certificate.getTbsCertificate().setIssuer(issuer); } } } }
 * 
 * private void setSubject() throws CertificateGeneratorException { Name subject = certificateConfig.getSubject(); if
 * (certificateConfig.isSharedConfig()) { RelativeDistinguishedName cn = X509Util.getCnFromName(subject);
 * 
 * if (cn == null) { throw new CertificateGeneratorException("Shared cert has no subject CN"); } Asn1OctetString
 * asn1PrintableString = new Asn1OctetString("new_cn"); asn1PrintableString
 * .setValue(ArrayUtils.addAll(cn.getAttributeTypeAndValueList().get(0).getValue().getContent().getValue(), ("_" +
 * (previousConfig.getSharedId() - 1)).getBytes()));
 * 
 * x509Certificate.getTbsCertificate().setSubject(subject);
 * certificateConfig.setSharedId(certificateConfig.getSharedId() + 1); } }
 * 
 * private void setValidity() { Validity validity = new Validity("validity");
 * 
 * if (certificateConfig.getNotBeforeTimeType() == TimeType.UTC_TIME) { Time time = new Time("validity",
 * TimeContextHint.NOT_BEFORE); time.makeSelection(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE.getBooleanValue(),
 * UniversalTagNumber.UTCTIME.getIntValue()); Asn1UtcTime utcTime = new Asn1UtcTime("utcTime");
 * utcTime.setIdentifier("notBefore"); utcTime.setValue(certificateConfig.getNotBeforeValue());
 * time.setValue(certificateConfig.getNotBeforeValue()); validity.setNotBefore(time); } else if
 * (certificateConfig.getNotBeforeTimeType() == TimeType.GENERALIZED_TIME) { Time time = new Time("validity",
 * TimeContextHint.NOT_BEFORE); time.makeSelection(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE.getBooleanValue(),
 * UniversalTagNumber.GENERALIZEDTIME.getIntValue()); Asn1GeneralizedTime generalTime = new
 * Asn1GeneralizedTime("generalTime"); generalTime.setIdentifier("notBefore");
 * generalTime.setValue(certificateConfig.getNotBeforeValue()); time.setValue(certificateConfig.getNotBeforeValue());
 * validity.setNotBefore(time); }
 * 
 * if (certificateConfig.getNotAfterTimeType() == TimeType.UTC_TIME) { Time time = new Time("validity",
 * TimeContextHint.NOT_AFTER); time.makeSelection(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE.getBooleanValue(),
 * UniversalTagNumber.UTCTIME.getIntValue()); Asn1UtcTime utcTime = new Asn1UtcTime("utcTime");
 * utcTime.setIdentifier("notAfter"); utcTime.setValue(certificateConfig.getNotAfterValue());
 * time.setValue(certificateConfig.getNotAfterValue()); validity.setNotAfter(time); } else if
 * (certificateConfig.getNotAfterTimeType() == TimeType.GENERALIZED_TIME) { Time time = new Time("validity",
 * TimeContextHint.NOT_AFTER); time.makeSelection(TagClass.UNIVERSAL, TagConstructed.PRIMITIVE.getBooleanValue(),
 * UniversalTagNumber.GENERALIZEDTIME.getIntValue()); Asn1GeneralizedTime generalTime = new
 * Asn1GeneralizedTime("generalTime"); generalTime.setIdentifier("notAfter");
 * generalTime.setValue(certificateConfig.getNotAfterValue());
 * x509Certificate.getTbsCertificate().getValidity().getNotBefore().getContent() .setModification(new
 * ByteArrayExplicitValueModification(generalTime.getValue().getValue().getBytes()));
 * time.setValue(certificateConfig.getNotAfterValue()); validity.setNotAfter(time); }
 * x509Certificate.getTbsCertificate().setValidity(validity); }
 * 
 * private void setUniqueIdentifiers() { if (certificateConfig.isIssuerUniqueIdPresent()) { Asn1BitString
 * issuerUniqueIdBitString = new Asn1BitString("issuerUniqueID", 1);
 * issuerUniqueIdBitString.setContent(certificateConfig.getIssuerUniqueId().getBytes());
 * issuerUniqueIdBitString.setUnusedBits(certificateConfig.getIssuerUniqueId().getUnusedBits());
 * x509Certificate.getTbsCertificate().setIssuerUniqueId(issuerUniqueIdBitString); } else {
 * x509Certificate.getTbsCertificate().setIssuerUniqueId(null); }
 * 
 * if (certificateConfig.isSubjectUniqueIdPresent()) { Asn1BitString subjectUniqueIdBitString = new
 * Asn1BitString("subjectUniqueID", 2);
 * subjectUniqueIdBitString.setContent(certificateConfig.getSubjectUniqueId().getBytes());
 * subjectUniqueIdBitString.setUnusedBits(certificateConfig.getSubjectUniqueId().getUnusedBits());
 * x509Certificate.getTbsCertificate().setSubjectUniqueId(subjectUniqueIdBitString); } else {
 * x509Certificate.getTbsCertificate().setSubjectUniqueId(null); } }
 * 
 * private void generateExtensions() throws CertificateGeneratorException { Extensions extensions = new
 * Extensions("extensions"); for (ExtensionConfig extensionConfig : certificateConfig.getExtensions().values()) { if
 * (extensionConfig.isPresent()) { Extension extension = extensionConfig.getExtensionFromConfig(certificateConfig,
 * previousConfig); extensions.addExtension(extension); } }
 * 
 * if (!extensions.getExtensionList().isEmpty() && certificateConfig.isExtensionsPresent()) { X509Explicit<Extensions>
 * explicitExtensions = new X509Explicit<>("extensionsExplicit", 3, extensions);
 * x509Certificate.getTbsCertificate().setExplicitExtensions(explicitExtensions); } }
 * 
 * private void setSignatureAlgorithm() { CertificateSignatureAlgorithmIdentifier algorithm = new
 * CertificateSignatureAlgorithmIdentifier("algorithm"); if (certificateConfig.isSelfSigned()) {
 * algorithm.setContent(certificateConfig.getSignatureAlgorithmOid().getBytes()); } else {
 * algorithm.setContent(previousConfig.getSignatureAlgorithmOid().getBytes()); }
 * x509Certificate.setSignatureAlgorithmIdentifier(algorithm); } }
 */