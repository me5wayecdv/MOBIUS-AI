package local.mobius.d061lab;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLHandshakeException;

/**
 * D-061 fixture: a lab-only target for the contained-capture harness.
 *
 * trustedCa flavor: trusts the per-run Mobius test CA for lab.mobius.local
 *   only. Expects (1) the proxied positive GET to succeed through normal
 *   hostname verification and (2) a DIRECT (proxy-bypassed) TLS connection
 *   to the IP literal to fail hostname verification, because the origin
 *   certificate names lab.mobius.local.
 * defaultTrust flavor: trusts only platform CAs. Expects the proxied GET to
 *   fail certificate validation against the test-CA-issued chain.
 *
 * Every outcome is one logcat line tagged D061FIXTURE; the harness reads
 * those lines as the app-side evidence. No verdict is written anywhere
 * else, so a crash or hang is an absence of lines and fails the run.
 */
public class MainActivity extends Activity {
    private static final String TAG = "D061FIXTURE";
    private static final String POSITIVE_URL = "https://lab.mobius.local:8443/hello?req=positive";
    private static final String UNTRUSTED_URL = "https://lab.mobius.local:8443/hello?req=untrusted";
    private static final String WRONGHOST_URL = "https://10.0.2.2:8443/hello?req=wronghost";
    private static final boolean IS_TRUSTED_CA = BuildConfig.FLAVOR.equals("trustedCa");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        new Thread(this::runSuite, "d061-suite").start();
    }

    private void runSuite() {
        if (IS_TRUSTED_CA) {
            Result positive = fetch(POSITIVE_URL, true);
            if (positive.status == 200 && positive.body.contains("\"req\":\"positive\"")) {
                Log.i(TAG, "POSITIVE_OK status=200");
            } else {
                Log.e(TAG, "POSITIVE_FAILED status=" + positive.status
                        + " error=" + positive.errorClass);
            }

            Result wronghost = fetch(WRONGHOST_URL, false);
            if (wronghost.errorClass != null
                    && wronghost.errorClass.equals(SSLPeerUnverifiedException.class.getSimpleName())) {
                Log.i(TAG, "WRONGHOST_REJECTED error=" + wronghost.errorClass);
            } else if (wronghost.errorClass != null
                    && wronghost.errorClass.equals(SSLHandshakeException.class.getSimpleName())) {
                Log.i(TAG, "WRONGHOST_REJECTED error=" + wronghost.errorClass);
            } else {
                Log.e(TAG, "WRONGHOST_NOTREJECTED status=" + wronghost.status
                        + " error=" + wronghost.errorClass);
            }
        } else {
            Result untrusted = fetch(UNTRUSTED_URL, true);
            if (untrusted.errorClass != null
                    && (untrusted.errorClass.equals(SSLHandshakeException.class.getSimpleName())
                        || untrusted.errorClass.equals(SSLPeerUnverifiedException.class.getSimpleName()))) {
                Log.i(TAG, "UNTRUSTED_REJECTED error=" + untrusted.errorClass);
            } else {
                Log.e(TAG, "UNTRUSTED_NOTREJECTED status=" + untrusted.status
                        + " error=" + untrusted.errorClass);
            }
        }
        Log.i(TAG, "SUITE_DONE flavor=" + BuildConfig.FLAVOR);
        finish();
    }

    private static class Result {
        int status = -1;
        String body = "";
        String errorClass = null;
    }

    /** Uses the system proxy when useSystemProxy, otherwise Proxy.NO_PROXY. */
    private Result fetch(String url, boolean useSystemProxy) {
        Result r = new Result();
        HttpsURLConnection conn = null;
        try {
            URL u = new URL(url);
            if (useSystemProxy) {
                conn = (HttpsURLConnection) u.openConnection();
            } else {
                conn = (HttpsURLConnection) u.openConnection(Proxy.NO_PROXY);
            }
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setRequestProperty("X-D061-Fixture", BuildConfig.FLAVOR);
            r.status = conn.getResponseCode();
            InputStream in = r.status >= 400 ? conn.getErrorStream() : conn.getInputStream();
            if (in != null) {
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] tmp = new byte[1024];
                int n;
                while ((n = in.read(tmp)) != -1) {
                    buf.write(tmp, 0, n);
                }
                r.body = new String(buf.toByteArray(), StandardCharsets.UTF_8);
            }
        } catch (SSLHandshakeException | SSLPeerUnverifiedException e) {
            r.errorClass = e.getClass().getSimpleName();
        } catch (Exception e) {
            r.errorClass = e.getClass().getSimpleName();
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
        return r;
    }
}
