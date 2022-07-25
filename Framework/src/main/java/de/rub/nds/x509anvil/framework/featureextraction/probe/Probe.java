package de.rub.nds.x509anvil.framework.featureextraction.probe;

import de.rub.nds.x509anvil.framework.featureextraction.probe.result.ProbeResult;
import de.rub.nds.x509anvil.framework.verifier.VerifierAdapter;

public abstract class Probe {
    private final VerifierAdapter verifierAdapter;

    public Probe(VerifierAdapter verifierAdapter) {
        this.verifierAdapter = verifierAdapter;
    }

    protected VerifierAdapter getVerifierAdapter() {
        return verifierAdapter;
    }

}
