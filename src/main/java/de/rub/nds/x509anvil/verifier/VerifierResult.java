package de.rub.nds.x509anvil.verifier;

public class VerifierResult {
    private final boolean valid;

    public VerifierResult(boolean valid) {
        this.valid = valid;
    }

    public boolean isValid() {
        return valid;
    }
}
