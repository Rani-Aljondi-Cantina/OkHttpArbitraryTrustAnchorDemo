package com.example.ranialjondi.okhttparbitrarytrustanchordemo;

import android.content.Intent;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.webkit.WebView;
import android.widget.Button;
import android.widget.Toast;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class MainActivity extends AppCompatActivity {

    final String TAG = "MainActivityTag";


    /**
     * Tests are rudimentary: will reject host path if intermediate CA doesn't contain a pin in the pinstore. Demonstrates
     * how pinning imposes requirements on certificate to whatever client wants.
     * <p>
     * <p>
     * Certificate pinning handled via fallback method: certificate only needs to contain any one of the keys in the truststore to be accepted.
     * <p>
     * <p>
     * To see different scenarios: change certificatePinner in okHttpClient initialization to one of the ceritificate pinners below
     * <p>
     * if a valid intermediate key is used: will open webview with content on publicobject.com
     * otherwise, will return
     */
    String prefix = "http://";
    String hostname = "publicobject.com";
    String wsPrefix = "wss://";
    String wssAddress = "139.68.198.155:8082";


    OkHttpClient rejectingClient = new OkHttpClient.Builder().certificatePinner(certificatePinner1).build();


    Request request = new Request.Builder()
            .url(wsPrefix + wssAddress)
            .build();

    WebView webView;

    Intent intent;

    Button button_good_keyset;
    Button button_bad_keyset;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        intent = new Intent(this, WebViewActivity.class);
        webView = (WebView) findViewById(R.id.import_web_view);

        button_good_keyset = (Button) findViewById(R.id.button_good_keyset);
        button_good_keyset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new RivieraConnectTask(getUnsafeOkHttpClient()).execute();
            }
        });

        button_bad_keyset = (Button) findViewById(R.id.button_bad_keyset);
        button_bad_keyset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new RivieraConnectTask(rejectingClient).execute();
            }
        });
    }

    private class RivieraConnectTask extends AsyncTask<Void, Void, Boolean> {

        String html = "";

        OkHttpClient okHttpClient;

        RivieraConnectTask(OkHttpClient okHttpClient) {
            this.okHttpClient = okHttpClient;
        }

        Response run() throws IOException {
            Response response;
            Call call = okHttpClient.newCall(request);
            Log.e(TAG, "" + call.toString());
            response = call.execute();
            return response;
        }

        @Override
        protected void onPreExecute() {
            super.onPreExecute();
        }

        @Override
        protected Boolean doInBackground(Void... params) {
            try {
                Response response = run();
                Log.e(TAG, response.code() + "");
                ResponseBody body = response.body();
                List<Certificate> peerCerts = response.handshake().peerCertificates();
                X509Certificate x509Certificate = (X509Certificate) peerCerts.get(0);
                Log.e(TAG, x509Certificate.getIssuerDN().getName());
                if (body == null) {
                    throw new NullPointerException("Response not received from host");
                } else html = body.string();
            } catch (SSLPeerUnverifiedException spu) {
                Log.e(TAG, spu.getMessage());
                return false;
            } catch (IOException e) {
                Log.e(TAG, e.getMessage());
                return false;
            }
            return true;
        }

        @Override
        protected void onPostExecute(Boolean certificatePinFound) {
            super.onPostExecute(certificatePinFound);
            if (!certificatePinFound) {
                Toast toast = Toast.makeText(getApplicationContext(), "Certificate Pinning Failure! Public key not found!", Toast.LENGTH_SHORT);
                toast.show();
            }
            Bundle bundle = new Bundle();
            Log.e(TAG, html);
            bundle.putString(Keys.htmlKey, html);
            intent.putExtras(bundle);
            startActivity(intent);
            //webView.loadData(html, "text/html; charset=utf-8", "UTF-8");
        }

        @Override
        protected void onCancelled() {
            super.onCancelled();
        }
    }

    private static OkHttpClient getUnsafeOkHttpClient() {
        try {
            // Create a trust manager that does not validate certificate chains
            final TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[]{};
                        }
                    }
            };

            // Install the all-trusting trust manager
            final SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            // Create an ssl socket factory with our all-trusting manager
            final SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            OkHttpClient.Builder builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslSocketFactory, (X509TrustManager) trustAllCerts[0]);
            builder.hostnameVerifier(new HostnameVerifier() {
                @Override
                public boolean verify(String hostname, SSLSession session) {
                    return true;
                }
            });

            OkHttpClient okHttpClient = builder.build();
            return okHttpClient;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    KeyStore readKeyStore() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream fis = null;
            try {
                fis = (FileInputStream) this.getResources().openRawResource(R.raw.bose_truststore);
                ks.load(fis, "ritter".toCharArray());
            } finally {
                if (fis != null) {
                    fis.close();
                }
            }
            return ks;
    }



}

