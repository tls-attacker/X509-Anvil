/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.suite.tests.basicfields.serialnumber;

import de.rub.nds.anvilcore.annotation.AnvilTest;
import de.rub.nds.anvilcore.annotation.IpmLimitations;
import de.rub.nds.x509anvil.framework.annotation.ChainLength;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilTest;
import de.rub.nds.x509anvil.framework.anvil.X509VerifierRunner;
import de.rub.nds.x509anvil.framework.verifier.VerifierException;
import de.rub.nds.x509anvil.framework.x509.generator.CertificateGeneratorException;
import de.rub.nds.x509anvil.framework.x509.generator.modifier.X509CertificateConfigModifier;
import org.junit.jupiter.api.TestInfo;

import java.math.BigInteger;

public class NegativeSerialNumberTests extends X509AnvilTest {

    @ChainLength(minLength = 2)
    @IpmLimitations(identifiers = "entity:serial_number")
    @AnvilTest(id = "basic-d2c3455637")
    public void negativeSerialNumberEntity(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertValid(
                testRunner,
                true,
                (X509CertificateConfigModifier)
                        config -> config.setSerialNumber(BigInteger.valueOf(-1337)), testInfo);
    }

    @ChainLength(minLength = 3)
    @IpmLimitations(identifiers = "inter0:serial_number")
    @AnvilTest(id = "basic-dc9c549b5f")
    public void negativeSerialNumberIntermediate(X509VerifierRunner testRunner, TestInfo testInfo)
            throws VerifierException, CertificateGeneratorException {
        assertValid(
                testRunner,
                false,
                (X509CertificateConfigModifier)
                        config -> config.setSerialNumber(BigInteger.valueOf(-1337)), testInfo);
    }
}
