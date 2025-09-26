/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.x509.config;

import de.rub.nds.asn1.model.Asn1ObjectIdentifier;
import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.constants.DirectoryStringChoiceType;
import de.rub.nds.x509attacker.constants.X500AttributeType;
import de.rub.nds.x509attacker.constants.X509ExtensionType;
import de.rub.nds.x509attacker.context.X509Context;
import de.rub.nds.x509attacker.filesystem.CertificateFileWriter;
import de.rub.nds.x509attacker.x509.X509CertificateChain;
import de.rub.nds.x509attacker.x509.model.*;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class X509Util {
    public static Extension getExtensionByOid(
            X509Certificate x509Certificate, X509ExtensionType extensionType) {
        try {
            return x509Certificate
                    .getTbsCertificate()
                    .getExplicitExtensions()
                    .getInnerField()
                    .getExtensionList()
                    .stream()
                    .filter(
                            extension ->
                                    extension
                                            .getExtnID()
                                            .getValue()
                                            .getValue()
                                            .equals(extensionType.getOid().toString()))
                    .collect(Collectors.toList())
                    .get(0);
        } catch (IndexOutOfBoundsException e) {
            throw new IllegalArgumentException("Extensions not found");
        }
    }

    public static void exportCertificates(
            List<X509Certificate> certificateChain, String directory) {
        X509CertificateChain x509CertificateChain = new X509CertificateChain(certificateChain);
        if (x509CertificateChain.size() >= 1) {
            writeCertificate(
                    directory, "root_cert", x509CertificateChain.getCertificateList().get(0));
        }
        if (x509CertificateChain.size() >= 2) {
            writeCertificate(
                    directory,
                    "leaf_cert",
                    x509CertificateChain.getCertificateList().get(x509CertificateChain.size() - 1));
        }
        if (x509CertificateChain.size() >= 3) {
            x509CertificateChain
                    .getCertificateList()
                    .subList(1, x509CertificateChain.size() - 1)
                    .forEach(
                            x ->
                                    writeCertificate(
                                            directory,
                                            "inter_cert_" + (certificateChain.indexOf(x) - 1),
                                            x));
        }
    }

    private static void writeCertificate(
            String directory, String filename, X509Certificate certificate) {
        try {
            String certificateFileName = filename + ".pem";
            File dir = new File(directory);
            if (!dir.exists()) {
                if (!dir.mkdirs()) {
                    throw new IOException("Could not create directory " + dir.getAbsolutePath());
                }
            }
            CertificateFileWriter certificateFileWriter =
                    new CertificateFileWriter(new File(directory + "/" + certificateFileName));
            certificateFileWriter.writeCertificate(
                    certificate
                            .getSerializer(new X509Chooser(null, new X509Context()))
                            .serialize());
            certificateFileWriter.close();
        } catch (IOException e) {
            throw new RuntimeException("Error writing Certificate to PEM: " + e);
        }
    }

    public static RelativeDistinguishedName getRdnFromName(Name name, X500AttributeType oid) {
        for (RelativeDistinguishedName relativeDistinguishedName :
                name.getRelativeDistinguishedNames()) {
            if (relativeDistinguishedName.getAttributeTypeAndValueList().stream()
                    .anyMatch(
                            attributeTypeAndValue ->
                                    Objects.equals(
                                            attributeTypeAndValue.getAttributeTypeConfig(), oid))) {
                return relativeDistinguishedName;
            }
        }
        return null;
    }

    public static void addDnQualifierToName(Name name) {
        RelativeDistinguishedName newRdn = new RelativeDistinguishedName("new_dnq");
        AttributeTypeAndValue attributeTypeAndValue =
                new AttributeTypeAndValue("dnq", DirectoryStringChoiceType.PRINTABLE_STRING);
        Asn1ObjectIdentifier asn1ObjectIdentifier = new Asn1ObjectIdentifier("dnq");
        asn1ObjectIdentifier.setValue(X500AttributeType.DN_QUALIFIER.getOid().toString());
        attributeTypeAndValue.setType(asn1ObjectIdentifier);
        newRdn.addAttributeTypeAndValue(attributeTypeAndValue);
        name.addRelativeDistinguishedNames(newRdn);
    }
}
