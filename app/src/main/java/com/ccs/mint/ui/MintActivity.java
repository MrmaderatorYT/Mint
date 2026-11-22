package com.ccs.mint.ui;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.os.LocaleList;

import androidx.appcompat.app.AppCompatActivity;

import java.util.Locale;

/** Applies the saved language to Mint's UI without changing the device language. */
abstract class MintActivity extends AppCompatActivity {
    static final String ENGLISH = "en";
    static final String UKRAINIAN = "uk";
    private static final String LANGUAGE = "language";

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(localized(base));
    }

    static Context localized(Context context) {
        Configuration override = new Configuration();
        override.setLocales(new LocaleList(Locale.forLanguageTag(language(context))));
        return context.createConfigurationContext(override);
    }

    static String language(Context context) {
        return UKRAINIAN.equals(settings(context).getString(LANGUAGE, ENGLISH)) ? UKRAINIAN : ENGLISH;
    }

    void chooseLanguage(String language) {
        if (language.equals(language(this))) return;
        settings(this).edit().putString(LANGUAGE, language).apply();
        recreate();
    }

    private static SharedPreferences settings(Context context) {
        return context.getSharedPreferences("mint_ui", Context.MODE_PRIVATE);
    }
}
