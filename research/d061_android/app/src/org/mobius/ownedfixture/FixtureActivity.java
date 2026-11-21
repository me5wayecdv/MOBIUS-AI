package org.mobius.ownedfixture;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/** HELD owned test-app source. No APK build/install/launch is approved by this file.
 * Fixed local-only endpoints. One bounded empty-body GET. No arbitrary URL input,
 * user/system CA trust, trust-all verifier, redirect, cookie, token or key access.
 */
public final class FixtureActivity extends Activity {
    private static final String TAG = "MobiusOwnedFixture";
    private static final int PROXY_PORT = 18080;
    private static final int ORIGIN_PORT = 18443;
    private static final int MAX_BYTES = 8192;
    private boolean started = false;
    private String preparedNonce;
    private TextView view;
    private final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
    private boolean released = false;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        view = new TextView(this);
        view.setText("HELD owned network fixture prepared, no request sent");
        setContentView(view);
        String nonce = getIntent().getStringExtra("fixture_nonce");
        String phase = getIntent().getStringExtra("fixture_phase");
        if (state != null || nonce == null || !nonce.matches("[0-9a-f]{32}") || !"prepare".equals(phase)) {
            Log.i(TAG, "REFUSED fresh prepare required");
            return;
        }
        preparedNonce = nonce;
        Log.i(TAG, "OWNED_FIXTURE_PREPARED nonce=" + nonce + " pid=" + android.os.Process.myPid()
            + " uid=" + android.os.Process.myUid());
    }

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        final String nonce = intent.getStringExtra("fixture_nonce");
        if ("release".equals(intent.getStringExtra("fixture_phase")) && preparedNonce != null
                && preparedNonce.equals(nonce) && started && !released) {
            released = true;
            release.countDown();
            return;
        }
        if (!"commit".equals(intent.getStringExtra("fixture_phase")) || preparedNonce == null
                || !preparedNonce.equals(nonce) || started) {
            Log.i(TAG, "REFUSED mismatched or repeated commit");
            return;
        }
        started = true;
        new Thread(() -> {
            try {
                exchange(nonce);
                Log.i(TAG, "OWNED_FIXTURE_REQUEST_COMPLETED nonce=" + nonce);
                runOnUiThread(() -> view.setText("Owned fixture request completed"));
            } catch (Exception error) {
                Log.e(TAG, "OWNED_FIXTURE_FAILED nonce=" + nonce + " pid=" + android.os.Process.myPid() + " uid=" + android.os.Process.myUid()
                    + " class=" + error.getClass().getSimpleName());
                runOnUiThread(() -> view.setText("Owned fixture failed"));
            }
        }, "owned-fixture-network").start();
    }

    private SSLContext explicitAppTrust() throws Exception {
        Certificate certificate;
        try (InputStream input = getResources().openRawResource(R.raw.fixture_proxy_ca)) {
            certificate = CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
        KeyStore anchors = KeyStore.getInstance(KeyStore.getDefaultType());
        anchors.load(null, null);
        anchors.setCertificateEntry("this-run-public-proxy-ca-only", certificate);
        TrustManagerFactory managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        managers.init(anchors);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, managers.getTrustManagers(), null);
        return context;
    }

    private static String readHeaders(InputStream input) throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        while (bytes.size() < MAX_BYTES) {
            int value = input.read();
            if (value < 0) throw new java.io.EOFException("incomplete fixed response headers");
            bytes.write(value);
            byte[] data = bytes.toByteArray();
            int n = data.length;
            if (n >= 4 && data[n-4] == 13 && data[n-3] == 10 && data[n-2] == 13 && data[n-1] == 10)
                return new String(data, StandardCharsets.US_ASCII);
        }
        throw new java.io.IOException("response header bound");
    }

    private void exchange(String nonce) throws Exception {
        // A reviewed contained emulator harness must provide exactly this reverse
        // mapping to its owned loopback proxy. No network fallback is attempted.
        try (Socket tunnel = new Socket()) {
            tunnel.connect(new InetSocketAddress("127.0.0.1", PROXY_PORT), 5000);
            tunnel.setSoTimeout(5000);
            Log.i(TAG, "OWNED_FIXTURE_SOCKET nonce=" + nonce + " pid=" + android.os.Process.myPid()
                + " uid=" + android.os.Process.myUid() + " local_port=" + tunnel.getLocalPort()
                + " remote=127.0.0.1:" + PROXY_PORT);
            // Keep the connected app socket observable before sending CONNECT or
            // application bytes. No host-side request substitutes for this one.
            if (!release.await(10, java.util.concurrent.TimeUnit.SECONDS))
                throw new java.io.IOException("socket attribution release deadline");
            OutputStream output = tunnel.getOutputStream();
            output.write(("CONNECT 127.0.0.1:" + ORIGIN_PORT + " HTTP/1.1\r\nHost: 127.0.0.1:" + ORIGIN_PORT + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            output.flush();
            String connect = readHeaders(tunnel.getInputStream());
            if (!connect.startsWith("HTTP/1.1 200 ")) throw new java.io.IOException("CONNECT refused");
            try (SSLSocket tls = (SSLSocket) explicitAppTrust().getSocketFactory().createSocket(tunnel, "127.0.0.1", ORIGIN_PORT, true)) {
                tls.setSoTimeout(5000);
                SSLParameters parameters = tls.getSSLParameters();
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                tls.setSSLParameters(parameters);
                Log.i(TAG, "OWNED_FIXTURE_TLS_BEGIN nonce=" + nonce + " pid=" + android.os.Process.myPid()
                    + " uid=" + android.os.Process.myUid());
                tls.startHandshake();
                Log.i(TAG, "OWNED_FIXTURE_TLS_ESTABLISHED nonce=" + nonce + " pid=" + android.os.Process.myPid()
                    + " uid=" + android.os.Process.myUid());
                OutputStream secure = tls.getOutputStream();
                String request = "GET /receipt?nonce=" + nonce + " HTTP/1.1\r\nHost: 127.0.0.1:" + ORIGIN_PORT
                    + "\r\nAccept: application/json\r\nX-D061-Nonce: " + nonce + "\r\n\r\n";
                secure.write(request.getBytes(StandardCharsets.US_ASCII));
                secure.flush();
                InputStream response = tls.getInputStream();
                String headers = readHeaders(response);
                if (!headers.startsWith("HTTP/1.0 200 ") && !headers.startsWith("HTTP/1.1 200 "))
                    throw new java.io.IOException("origin status not 200");
                java.util.regex.Matcher match = java.util.regex.Pattern.compile("(?im)^Content-Length: ([0-9]{1,4})\\r$").matcher(headers);
                if (!match.find()) throw new java.io.IOException("missing bounded response length");
                int length = Integer.parseInt(match.group(1));
                if (length > 4096) throw new java.io.IOException("response body bound");
                byte[] body = new byte[length];
                int count = 0;
                while (count < length) {
                    int got = response.read(body, count, length-count);
                    if (got < 0) throw new java.io.EOFException("incomplete response body");
                    count += got;
                }
                String expected = "{\"nonce\": \"" + nonce + "\"}";
                if (!new String(body, StandardCharsets.UTF_8).equals(expected))
                    throw new java.io.IOException("response nonce mismatch");
            }
        }
    }
}
