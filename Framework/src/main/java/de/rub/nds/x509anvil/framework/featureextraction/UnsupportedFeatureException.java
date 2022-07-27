package de.rub.nds.x509anvil.framework.featureextraction;

public class UnsupportedFeatureException extends Exception {
    public UnsupportedFeatureException() {
        super();
    }

    public UnsupportedFeatureException(String message) {
        super(message);
    }

    public UnsupportedFeatureException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnsupportedFeatureException(Throwable cause) {
        super(cause);
    }

    protected UnsupportedFeatureException(String message, Throwable cause, boolean enableSuppression,
                             boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}