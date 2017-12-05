package com.example.ranialjondi.okhttparbitrarytrustanchordemo;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.webkit.WebView;

public class WebViewActivity extends AppCompatActivity {

    final String key = "html_key";

    WebView webView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_web_view);
        String htmlString = getIntent().getExtras().getString(Keys.htmlKey);
        webView = (WebView) findViewById(R.id.import_web_view);

        webView.loadData(htmlString, "text/html; charset=utf-8", "UTF-8");



    }
}
