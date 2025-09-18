/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.encoding;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayExplicitValueModification;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateModifier;

public class InvalidCertificateLengthTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @AnvilTest(id = "encoding-465dca8b34")
    public void shortLengthTagEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateModifier)
                        certificate ->
                                certificate
                                        .getLengthOctets()
                                        .setModifications(
                                                new ByteArrayExplicitValueModification(
                                                        new byte[] {(byte) 0x82, 0, 1})));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "encoding-bfa8982b92")
    public void shortLengthTagIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateModifier)
                        certificate ->
                                certificate
                                        .getLengthOctets()
                                        .setModifications(
                                                new ByteArrayExplicitValueModification(
                                                        new byte[] {(byte) 0x82, 0, 1})));
    }

    @ChainLength(minLength = 2)
    @AnvilTest(id = "encoding-c151dbb976")
    public void overflowingLengthTagEntity(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                true,
                (X509CertificateModifier)
                        certificate ->
                                certificate
                                        .getLengthOctets()
                                        .setModifications(
                                                new ByteArrayExplicitValueModification(
                                                        new byte[] {
                                                            (byte) 0x82, 0x07, (byte) 0xD0
                                                        })));
    }

    @ChainLength(minLength = 3)
    @AnvilTest(id = "encoding-0d3990e788")
    public void overflowingLengthTagIntermediate(X509VerifierRunner testRunner)
            throws VerifierException, CertificateGeneratorException {
        assertInvalid(
                testRunner,
                false,
                (X509CertificateModifier)
                        certificate ->
                                certificate
                                        .getLengthOctets()
                                        .setModifications(
                                                new ByteArrayExplicitValueModification(
                                                        new byte[] {
                                                            (byte) 0x82, 0x07, (byte) 0xD0
                                                        })));
    }
}
