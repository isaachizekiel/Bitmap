package com.izak.bitmap;

import androidx.appcompat.app.AppCompatActivity;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.ImageView;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;

import javax.security.auth.x500.X500Principal;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "MainActivity";
    public static final int WIDTH = 64;
    public static final int HEIGHT = 32;
    private static final String KEY_ALIAS = "Bitmap";

    private KeyStore ks;
    private final byte [] data = "Hello".getBytes(StandardCharsets.UTF_8);
    private byte [] signature;

    static class MyColor {
        int r;
        int b;
        int g;

        public MyColor(int r, int b, int g) {
            this.r = r;
            this.b = b;
            this.g = g;
        }
    }

    List<List<MyColor>> index = new ArrayList<>();

    Bitmap bitmap;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Left Colors
        List<MyColor> myColorList = new ArrayList<>();
        MyColor myColor = new MyColor(100, 0, 99);
        myColorList.add(myColor);

        myColor = new MyColor(100, 0, 75);
        myColorList.add(myColor);

        myColor = new MyColor(87, 0, 99);
        myColorList.add(myColor);

        myColor = new MyColor(49, 0, 100);
        myColorList.add(myColor);

        myColor = new MyColor(12, 0, 99);
        myColorList.add(myColor);

        myColor = new MyColor(0, 26, 100);
        myColorList.add(myColor);

        myColor = new MyColor(0, 64, 100);
        myColorList.add(myColor);

        myColor = new MyColor(0, 99, 100);
        myColorList.add(myColor);

        index.add(myColorList);


        // right colors
        myColorList = new ArrayList<>();
        myColor = new MyColor(100, 0, 0);
        myColorList.add(myColor);

        myColor = new MyColor(100, 38, 0);
        myColorList.add(myColor);

        myColor = new MyColor(100, 75, 0);
        myColorList.add(myColor);

        myColor = new MyColor(88, 100, 1);
        myColorList.add(myColor);

        myColor = new MyColor(49, 100, 0);
        myColorList.add(myColor);

        myColor = new MyColor(12, 100, 0);
        myColorList.add(myColor);

        myColor = new MyColor(0, 100, 26);
        myColorList.add(myColor);

        myColor = new MyColor(0, 100, 64);
        myColorList.add(myColor);

        index.add(myColorList);


        try {
            createKeys();
        } catch (NoSuchProviderException | NoSuchAlgorithmException
                | InvalidAlgorithmParameterException | KeyStoreException
                | CertificateException | IOException e) {
            e.printStackTrace();
        }

        try {
            sign();
        } catch (KeyStoreException | UnrecoverableEntryException | NoSuchAlgorithmException
                | InvalidKeyException | SignatureException | IOException | CertificateException e) {
            e.printStackTrace();
        }


        if (signature != null) {
            Log.e(TAG, "onCreate: We seem to have some values here");
        }

        boolean verified = false;
        try {
            verified = verify();
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException
                | IOException | UnrecoverableEntryException | InvalidKeyException
                | SignatureException e) {
            e.printStackTrace();
        }

        if (verified) Log.e(TAG, "onCreate: We are good to go!");



        bitmap = Bitmap.createBitmap(WIDTH, HEIGHT, Bitmap.Config.ARGB_8888);

        for (int i = 0, j = 0, x = 0, y = 0; i < signature.length; i ++) {
            if ((i != 0 || j != 0) && (i % 16 == 0)) j++;
            // now we are inside 16 x 16 byte array
            int my_char = signature[i];
            int byte_index = 0;
            while (byte_index < 8) {
                // when the binary encoding of 1 is different from 01 undefined behavior
                int r = 0, b = 0, g = 0;
                if ((my_char & 0x01) == 1) {
                    r = index.get(1).get(byte_index).r;
                    b = index.get(1).get(byte_index).b;
                    g = index.get(1).get(byte_index).g;
                } else {
                    r = index.get(0).get(byte_index).r;
                    b = index.get(0).get(byte_index).b;
                    g = index.get(0).get(byte_index).g;
                }

                if ((x != 0 || y != 0) && (x % WIDTH == 0)) { x = 0; y++; }

                x++;

                bitmap.setPixel(x % WIDTH, y % WIDTH, Color.rgb(r, g, b));

                byte_index++;
                my_char = my_char >> 1; // moving to the next bit

            }
        }

        Log.e(TAG, "onCreate: " + bitmap.getWidth() + " " + bitmap.getHeight());

        ImageView imageView = new ImageView(this);
        imageView.setImageBitmap(bitmap);
        setContentView(imageView);
    }

    private void createKeys() throws NoSuchProviderException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, KeyStoreException, CertificateException,
            IOException {
        ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        ks.load(null);

        // if (ks.containsAlias(KEY_ALIAS)) return;

        Log.e(TAG, "Generating new Keypair");

        Calendar start = new GregorianCalendar();
        Calendar end = new GregorianCalendar();
        end.add(Calendar.YEAR, 1);

        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance(SecurityConstants.TYPE_RSA, SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);
        AlgorithmParameterSpec spec = new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setCertificateSubject(new X500Principal("CN=" + KEY_ALIAS))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateSerialNumber(BigInteger.valueOf(1337))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime())
                .build();;

        kpGenerator.initialize(spec);

        KeyPair kp = kpGenerator.generateKeyPair();
        // END_INCLUDE(create_spec)
        Log.d(TAG, "Public Key is: " + kp.getPublic().toString());
    }

    private void sign() throws KeyStoreException, UnrecoverableEntryException,
            NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException,
            CertificateException {
        // BEGIN_INCLUDE(sign_load_keystore)
        ks = KeyStore.getInstance(SecurityConstants.KEYSTORE_PROVIDER_ANDROID_KEYSTORE);

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);

        /* If the entry is null, keys were never stored under this alias.
         * Debug steps in this situation would be:
         * -Check the list of aliases by iterating over Keystore.aliases(), be sure the alias
         *   exists.
         * -If that's empty, verify they were both stored and pulled from the same keystore
         *   "AndroidKeyStore"
         */
        if (entry == null) {
            Log.w(TAG, "No key found under alias: " + KEY_ALIAS);
            Log.w(TAG, "Exiting signData()...");
            return;
        }

        /* If entry is not a KeyStore.PrivateKeyEntry, it might have gotten stored in a previous
         * iteration of your application that was using some other mechanism, or been overwritten
         * by something else using the same keystore with the same alias.
         * You can determine the type using entry.getClass() and debug from there.
         */
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            Log.w(TAG, "Exiting signData()...");
            return;
        }
        // END_INCLUDE(sign_data)

        // BEGIN_INCLUDE(sign_create_signature)
        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        // Initialize Signature using specified private key
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());

        // Sign the data, store the result as a Base64 encoded String.
        s.update(data);
        signature = s.sign();

    }

    private boolean verify() throws KeyStoreException,
            CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableEntryException, InvalidKeyException, SignatureException {
        // Make sure the signature string exists.  If not, bail out, nothing to do.
        if (data == null) {
            Log.e(TAG, "verifyToken: Data is null");
            return false;
        }

        ks = KeyStore.getInstance("AndroidKeyStore");

        // Weird artifact of Java API.  If you don't have an InputStream to load, you still need
        // to call "load", or it'll crash.
        ks.load(null);

        // Load the key pair from the Android Key Store
        KeyStore.Entry entry = ks.getEntry(KEY_ALIAS, null);

        if (entry == null) {
            Log.e(TAG, "verifyToken: No key found under alias: " + KEY_ALIAS);
            return false;
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.e(TAG, "verifyToken: Not an instance of a PrivateKeyEntry");
            return false;
        }

        // This class doesn't actually represent the signature,
        // just the engine for creating/verifying signatures, using
        // the specified algorithm.
        Signature s = Signature.getInstance(SecurityConstants.SIGNATURE_SHA256withRSA);

        s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        return s.verify(signature);
    }

}