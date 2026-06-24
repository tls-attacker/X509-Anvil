package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.anvil.parameter.value.NotBeforeValue;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.NotBeforeProbeResult;
import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierResult;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateChainConfig;
import de.rub.nds.x509anvil.framework.x509.config.X509CertificateConfigUtil;
import de.rub.nds.x509attacker.config.X509CertificateConfig;
import de.rub.nds.x509attacker.constants.ValidityEncoding;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

public class NotBeforeProbe extends SimpleProbe{

    private final NotBeforeValue notBeforeValue;

    public NotBeforeProbe(NotBeforeValue notBeforeValue) {
        this.notBeforeValue = notBeforeValue;
    }

    @Override
    protected X509CertificateChainConfig prepareConfig() {
        X509CertificateChainConfig x509CertificateChainConfig =
                X509CertificateConfigUtil.createBasicConfig(2);
        X509CertificateConfig certificateConfig = x509CertificateChainConfig.getEntityCertificateConfig();

        switch (notBeforeValue) {
            case UTC_TIME:
                certificateConfig.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                certificateConfig.setNotBefore(
                        new DateTime(2022, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
            case UTC_TIME_EARLIEST:
                certificateConfig.setDefaultNotBeforeEncoding(ValidityEncoding.UTC);
                certificateConfig.setNotBefore(
                        new DateTime(1950, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
            case GENERALIZED_TIME:
                certificateConfig.setDefaultNotBeforeEncoding(
                        ValidityEncoding.GENERALIZED_TIME_UTC);
                certificateConfig.setNotBefore(
                        new DateTime(2022, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
            case GENERALIZED_TIME_BEFORE_1950:
                certificateConfig.setDefaultNotBeforeEncoding(
                        ValidityEncoding.GENERALIZED_TIME_UTC);
                certificateConfig.setNotBefore(
                        new DateTime(1950, 1, 1, 0, 0, DateTimeZone.forID("UTC")));
                break;
        }

        return x509CertificateChainConfig;
    }

    @Override
    protected ProbeResult createResult(VerifierResult verifierResult) {
        return new NotBeforeProbeResult(notBeforeValue, verifierResult.isValid());
    }
}
