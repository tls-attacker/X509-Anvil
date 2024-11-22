/**
 * Framework - A tool for creating arbitrary certificates
 * <p>
 * Copyright 2014-2024 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
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
        super(new ParameterIdentifier(X509AnvilParameterType.SERIAL_NUMBER, parameterScope), BigInteger.class);
    }

    public SerialNumberParameter(BigInteger selectedValue, ParameterScope parameterScope) {
        this(parameterScope);
        setSelectedValue(selectedValue);
    }

    @Override
    protected DerivationParameter<X509CertificateChainConfig, BigInteger> generateValue(BigInteger selectedValue) {
        return new SerialNumberParameter(selectedValue, getParameterIdentifier().getParameterScope());
    }

    @Override
    public List<DerivationParameter<X509CertificateChainConfig, BigInteger>>
        getNonNullParameterValues(DerivationScope derivationScope) {
        List<DerivationParameter<X509CertificateChainConfig, BigInteger>> parameterValues = new ArrayList<>();
        parameterValues.add(generateValue(BigInteger.valueOf(1))); // Smallest valid serial number
        parameterValues.add(generateValue(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16))); // Biggest
                                                                                                            // valid
                                                                                                            // serial
                                                                                                            // number
                                                                                                            // (20
                                                                                                            // octets)

        // TODO: These values must be handled gracefully but do not have to be accepted
//        parameterValues.add(generateValue(BigInteger.valueOf(-1)));
//        parameterValues.add(generateValue(
//            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16)));
        return parameterValues;
    }

    @Override
    public void applyToCertificateConfig(X509CertificateConfig certificateConfig, DerivationScope derivationScope) {
        certificateConfig.setSerialNumber(getSelectedValue());
    }
}
