/*
 * X.509-Anvil - A Compliancy Evaluation Tool for X.509 Certificates.
 *
 * Copyright 2014-2025 Ruhr University Bochum, Paderborn University, Technology Innovation Institute, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.x509anvil.framework.anvil.parameter;

import de.rub.nds.anvilcore.model.DerivationScope;
import de.rub.nds.anvilcore.model.parameter.DerivationParameter;
import de.rub.nds.anvilcore.model.parameter.ParameterIdentifier;
import de.rub.nds.anvilcore.model.parameter.ParameterScope;
import de.rub.nds.x509anvil.framework.anvil.X509AnvilParameterType;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class SerialNumberParameter extends CertificateSpecificParameter<BigInteger> {

    public SerialNumberParameter(ParameterScope parameterScope) {
        super(
                new ParameterIdentifier(X509AnvilParameterType.SERIAL_NUMBER, parameterScope),
                BigInteger.class);
    }

    public SerialNumberParameter(BigInteger selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, BigInteger> generateValue(
            BigInteger selectedValue) {
        return new SerialNumberParameter(
                selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, BigInteger>>
            getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, BigInteger>> parameterValues =
                new ArrayList<>();
        parameterValues.add(generateValue(BigInteger.valueOf(1))); // Smallest valid serial number
        parameterValues.add(
                generateValue(
                        new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16))); // Biggest
        // valid
        // serial
        // number
        // (20
        // octets)
        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(
            X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setSerialNumber(getSelectedValue());
    }
}
