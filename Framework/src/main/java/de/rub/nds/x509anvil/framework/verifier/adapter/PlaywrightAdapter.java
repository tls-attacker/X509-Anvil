package de.rub.nds.x509anvil.framework.verifier.adapter;

import de.rub.nds.x509anvil.framework.verifier.PlaywrightConfig;

import java.io.IOException;
import java.net.URL;

public class PlaywrightAdapter extends TlsServerAuthVerifierAdapter {
    private String browser;
    public int realPort;

    public PlaywrightAdapter(String browser, String hostname, int port) {
        super(hostname, port);
        this.browser = browser;
    }

    public static PlaywrightAdapter fromConfig(PlaywrightConfig config) {
        return new PlaywrightAdapter(config.getBrowser(), config.getHostname(), config.getPort());
    }

    @Override
    public void runCommandInBackground() {
        try {
            new URL("http://localhost:3000/"+browser+"?target="+realPort).openConnection().getInputStream().close();
        } catch (IOException e) {
            //
        }
    }
}
