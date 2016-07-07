package com.education.myencrypt;

import android.text.TextUtils;
import android.util.Base64;

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

/**
 * Created by zhonghang on 16/7/7.
 */

public class EncryptUtils {
    private static final String MODULUS = "100631058000714094813874361191853577129731636346684218206605779824931626830750623070803100189781211343851763275329364056640619755337779928985272486091431384128027213365372009648233171894708338213168824861061809490615593530405056055952622249066180336803996949444124622212096805545953751253607916170340397933039";
    private static final String PUB_KEY = "65537";
    private static final String PRI_KEY = "26900155715313643087786516528374548998821559381075740707715132776187148793016466508650068087107695523642202737697714709374658856733792614490943874205956727606674634563665154616758939576547663715234643273055658829482813503959459653708062875625210008961239643775661357655599312857249418610810177817213648575161";

    public static String rsaEncrypt(String content) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec
                    (new BigInteger(MODULUS), new BigInteger(PUB_KEY));
            cipher.init(Cipher.ENCRYPT_MODE, factory.generatePublic(publicKeySpec));
            byte[] aFinal = cipher.doFinal(content.getBytes("UTF-8"));
            return Base64.encodeToString(aFinal, Base64.DEFAULT);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String rsaDecrypt(String content) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(MODULUS), new BigInteger(PRI_KEY));
            cipher.init(Cipher.DECRYPT_MODE, factory.generatePrivate(privateKeySpec));
            byte[] aFinal = cipher.doFinal(Base64.decode(content, Base64.DEFAULT));
            return new String(aFinal, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String base64Encrypt(String content) {
        try {
            return Base64.encodeToString(content.getBytes("UTF-8"), Base64.DEFAULT);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String base64Decrypt(String content) {
        try {
            return new String(Base64.decode(content.getBytes("UTF-8"), Base64.DEFAULT));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String md5(String content) {
        if (!TextUtils.isEmpty(content)) {
            try {
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                byte[] digest = md5.digest(content.getBytes("UTF-8"));

                StringBuilder builder = new StringBuilder();
                for (byte b : digest) {
                    builder.append(String.format("%02x", b));
                }
                return builder.toString();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }

        }
        return null;
    }

    public static String desDecrypt(String key, String content) {
        try {
            byte[] bytes = key.getBytes("UTF-8");
            byte[] temp = new byte[32];
            System.arraycopy(bytes, 0, temp, 0, Math.min(bytes.length, temp.length));
            SecretKey secretKey = new SecretKeySpec(temp, "AES");
            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] aFinal = cipher.doFinal(Base64.decode(content, Base64.DEFAULT));
            return new String(aFinal, "UTF-8");

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String desEncrypt(String key, String content) {

        try {
            byte[] bytes = key.getBytes("UTF-8");
            byte[] temp = new byte[32];
            System.arraycopy(bytes, 0, temp, 0, Math.min(bytes.length, temp.length));
            SecretKey secretKey = new SecretKeySpec(temp, "AES");
            Cipher cipher = Cipher.getInstance("AES");


            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] aFinal = cipher.doFinal(content.getBytes("UTF-8"));
            String encrypt = Base64.encodeToString(aFinal, Base64.DEFAULT);
            return encrypt;

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

}
