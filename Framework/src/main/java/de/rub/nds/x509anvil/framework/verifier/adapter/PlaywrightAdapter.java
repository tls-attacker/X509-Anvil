package de.rub.nds.x509anvil.framework.verifier.adapter;

import de.rub.nds.x509anvil.framework.verifier.PlaywrightConfig;
import de.rub.nds.x509anvil.framework.verifier.TlsAuthVerifierAdapterConfig;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

public class PlaywrightAdapter extends TlsServerAuthVerifierAdapter {
    private URL target;
    public PlaywrightAdapter(String browser, String hostname, int port) {
        super(hostname, port);
        try {
            this.target = new URL("http://localhost:3000/"+browser+"?target="+port);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public static PlaywrightAdapter fromConfig(PlaywrightConfig config) {
        return new PlaywrightAdapter(config.getBrowser(), config.getHostname(), config.getPort());
    }

    @Override
    public void runCommandInBackground() {
        try {
            target.openConnection().getInputStream().close();
        } catch (IOException e) {
            //
            e.printStackTrace();
        }
    }
}
