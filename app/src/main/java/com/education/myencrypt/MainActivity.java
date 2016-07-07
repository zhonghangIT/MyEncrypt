package com.education.myencrypt;

import android.os.Bundle;
import android.support.design.widget.TextInputEditText;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import butterknife.ButterKnife;
import butterknife.InjectView;
import butterknife.OnClick;

public class MainActivity extends AppCompatActivity {
    @InjectView(R.id.edittext_password)
    TextInputEditText edittextPassword;
    @InjectView(R.id.textview_encrypt)
    TextView textviewEncrypt;
    @InjectView(R.id.button_md5)
    Button buttonMd5;
    @InjectView(R.id.button_encrypt)
    Button buttonEncrypt;
    @InjectView(R.id.button_decrypt)
    Button buttonDecrypt;
    @InjectView(R.id.button_base64_encrypt)
    Button buttonBase64Encrypt;
    @InjectView(R.id.button_base64_decrypt)
    Button buttonBase64Decrypt;
    @InjectView(R.id.button_rsa_encrypt)
    Button buttonRsaEncrypt;
    @InjectView(R.id.button_rsa_decrypt)
    Button buttonRsaDecrypt;




    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ButterKnife.inject(this);

    }


    @OnClick({R.id.button_md5, R.id.button_encrypt, R.id.button_decrypt, R.id.button_base64_encrypt, R.id.button_base64_decrypt, R.id.button_rsa_encrypt, R.id.button_rsa_decrypt})
    public void onClick(View view) {
        switch (view.getId()) {
            case R.id.button_md5:
                String encrypt = EncryptUtils.md5(edittextPassword.getText().toString());
                textviewEncrypt.setText(encrypt);
                break;
            case R.id.button_encrypt:
                break;
            case R.id.button_decrypt:
                break;
            case R.id.button_base64_encrypt:
                String encrypt64 = EncryptUtils.base64Encrypt(edittextPassword.getText().toString());
                textviewEncrypt.setText(encrypt64);
                break;
            case R.id.button_base64_decrypt:
                String content = EncryptUtils.base64Decrypt(textviewEncrypt.getText().toString());
                textviewEncrypt.setText(content);
                break;
            case R.id.button_rsa_encrypt:
                break;
            case R.id.button_rsa_decrypt:
                break;
        }
    }
}
