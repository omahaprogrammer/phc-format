package com.omahaprogrammer.crypto;

import static org.junit.Assert.*;

import com.omahaprogrammer.crypto.function.*;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class PHCTest {
    private static Base64.Encoder encoder = Base64.getEncoder().withoutPadding();

    @Test
    public void pbkdf2Test1() {
        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withSalt(salt)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA1)
                .withParam(PBKDF2.C, 1)
                .withParam(PBKDF2.LENGTH, 20)
                .hash(password);
        var hash = encoder.encodeToString(new byte[]{0x0c, 0x60, (byte)0xc8, 0x0f, (byte)0x96, 0x1f, 0x0e, 0x71,
                (byte)0xf3, (byte)0xa9, (byte)0xb5, 0x24, (byte)0xaf, 0x60, 0x12, 0x06,
                0x2f, (byte)0xe0, 0x37, (byte)0xa6});

        assertEquals(String.format("$pbkdf2$alg=HmacSHA1,c=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void pbkdf2Test2() {
        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withSalt(salt)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA1)
                .withParam(PBKDF2.C, 2)
                .withParam(PBKDF2.LENGTH, 20)
                .hash(password);
        var hash = encoder.encodeToString(new byte[]{(byte)0xea, 0x6c, 0x01, 0x4d, (byte)0xc7, 0x2d, 0x6f, (byte)0x8c,
                (byte)0xcd, 0x1e, (byte)0xd9, 0x2a, (byte)0xce, 0x1d, 0x41, (byte)0xf0,
                (byte)0xd8, (byte)0xde, (byte)0x89, 0x57});

        assertEquals(String.format("$pbkdf2$alg=HmacSHA1,c=2$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void pbkdf2Test3() {
        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withSalt(salt)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA1)
                .withParam(PBKDF2.C, 4096)
                .withParam(PBKDF2.LENGTH, 20)
                .hash(password);
        var hash = encoder.encodeToString(new byte[]{0x4b, 0x00, 0x79, 0x01, (byte)0xb7, 0x65, 0x48, (byte)0x9a,
                (byte)0xbe, (byte)0xad, 0x49, (byte)0xd9, 0x26, (byte)0xf7, 0x21, (byte)0xd0,
                0x65, (byte)0xa4, 0x29, (byte)0xc1});

        assertEquals(String.format("$pbkdf2$alg=HmacSHA1,c=4096$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void pbkdf2Test4() {
        char[] password = "password".toCharArray();
        byte[] salt = "salt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withSalt(salt)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA1)
                .withParam(PBKDF2.C, 16777216)
                .withParam(PBKDF2.LENGTH, 20)
                .hash(password);
        var hash = encoder.encodeToString(new byte[]{(byte)0xee, (byte)0xfe, 0x3d, 0x61, (byte)0xcd, 0x4d, (byte)0xa4, (byte)0xe4,
                (byte)0xe9, (byte)0x94, 0x5b, 0x3d, 0x6b, (byte)0xa2, 0x15, (byte)0x8c,
                0x26, 0x34, (byte)0xe9, (byte)0x84});

        assertEquals(String.format("$pbkdf2$alg=HmacSHA1,c=16777216$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void pbkdf2Test5() {
        char[] password = "passwordPASSWORDpassword".toCharArray();
        byte[] salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withSalt(salt)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA1)
                .withParam(PBKDF2.C, 4096)
                .withParam(PBKDF2.LENGTH, 25)
                .hash(password);
        var hash = encoder.encodeToString(new byte[]{0x3d, 0x2e, (byte)0xec, 0x4f, (byte)0xe4, 0x1c, (byte)0x84, (byte)0x9b,
                (byte)0x80, (byte)0xc8, (byte)0xd8, 0x36, 0x62, (byte)0xc0, (byte)0xe4, 0x4a,
                (byte)0x8b, 0x29, 0x1a, (byte)0x96, 0x4c, (byte)0xf2, (byte)0xf0, 0x70,
                0x38});

        assertEquals(String.format("$pbkdf2$alg=HmacSHA1,c=4096$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void pbkdf2Test6() {
        char[] password = "pass\0word".toCharArray();
        byte[] salt = "sa\0lt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withSalt(salt)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA1)
                .withParam(PBKDF2.C, 4096)
                .withParam(PBKDF2.LENGTH, 16)
                .hash(password);
        var hash = encoder.encodeToString(new byte[]{0x56, (byte)0xfa, 0x6a, (byte)0xa7, 0x55, 0x48, 0x09, (byte)0x9d,
                (byte)0xcc, 0x37, (byte)0xd7, (byte)0xf0, 0x34, 0x25, (byte)0xe0, (byte)0xc3});

        assertEquals(String.format("$pbkdf2$alg=HmacSHA1,c=4096$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA224() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA224)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA224,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA256() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA256)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA256,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA384() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA384)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA384,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA512() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA512)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA512,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA3_224() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA3_224)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA3-224,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA3_256() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA3_256)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA3-256,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA3_384() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA3_384)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA3-384,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void pbkdf2HmacSHA3_512() {
        char[] password = "password".toCharArray();
        PHC phc = PHC.builder(PHCFunction.PBKDF2)
                .withRandomSalt(16)
                .withParam(PBKDF2.ALG, PBKDF2.Algorithm.HMAC_SHA3_512)
                .withParam(PBKDF2.C, 4096)
                .hash(password);

        assertEquals(String.format("$pbkdf2$alg=HmacSHA3-512,c=4096$%s$%s", encoder.encodeToString(phc.getSalt()), encoder.encodeToString(phc.getHashedPassword())), phc.toString());
    }

    @Test
    public void testArgon2iTest1() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 65536)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0"));

        assertEquals(String.format("$argon2i$m=65536,t=2,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest2() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 1048576)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41"));

        assertEquals(String.format("$argon2i$m=1048576,t=2,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest3() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 262144)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb"));

        assertEquals(String.format("$argon2i$m=262144,t=2,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest4() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 256)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f"));

        assertEquals(String.format("$argon2i$m=256,t=2,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest5() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 256)
                .withParam(Argon2i.P, 2)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61"));

        assertEquals(String.format("$argon2i$m=256,t=2,p=2$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest6() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 1)
                .withParam(Argon2i.M, 65536)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf"));

        assertEquals(String.format("$argon2i$m=65536,t=1,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest7() {
        char[] password = "password".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 4)
                .withParam(Argon2i.M, 65536)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b"));

        assertEquals(String.format("$argon2i$m=65536,t=4,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest8() {
        char[] password = "differentpassword".toCharArray();
        byte[] salt = "somesalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 65536)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee"));

        assertEquals(String.format("$argon2i$m=65536,t=2,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2iTest9() {
        char[] password = "password".toCharArray();
        byte[] salt = "diffsalt".getBytes(StandardCharsets.US_ASCII);
        PHC phc = PHC.builder(PHCFunction.ARGON2_I)
                .withSalt(salt)
                .withParam(Argon2i.T, 2)
                .withParam(Argon2i.M, 65536)
                .withParam(Argon2i.P, 1)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271"));

        assertEquals(String.format("$argon2i$m=65536,t=2,p=1$%s$%s", encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2dTest1() {
        char[] password = new char[32];
        byte[] salt = new byte[16];
        byte[] secret = new byte[8];
        byte[] data = new byte[12];
        Arrays.fill(password, '\u0001');
        Arrays.fill(salt, (byte)0x02);
        Arrays.fill(secret, (byte)0x03);
        Arrays.fill(data, (byte)0x04);
        PHC phc = PHC.builder(PHCFunction.ARGON2_D)
                .withSalt(salt)
                .withParam(Argon2d.T, 3)
                .withParam(Argon2d.M, 32)
                .withParam(Argon2d.P, 4)
                .withParam(Argon2d.KEY_ID, secret)
                .withParam(Argon2d.DATA, data)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb"));

        assertEquals(String.format("$argon2d$m=32,t=3,p=4,keyid=%s,data=%s$%s$%s", encoder.encodeToString(secret), encoder.encodeToString(data), encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testArgon2idTest1() {
        char[] password = new char[32];
        byte[] salt = new byte[16];
        byte[] secret = new byte[8];
        byte[] data = new byte[12];
        Arrays.fill(password, '\u0001');
        Arrays.fill(salt, (byte)0x02);
        Arrays.fill(secret, (byte)0x03);
        Arrays.fill(data, (byte)0x04);
        PHC phc = PHC.builder(PHCFunction.ARGON2_ID)
                .withSalt(salt)
                .withParam(Argon2id.T, 3)
                .withParam(Argon2id.M, 32)
                .withParam(Argon2id.P, 4)
                .withParam(Argon2id.KEY_ID, secret)
                .withParam(Argon2id.DATA, data)
                .hash(password);
        var hash = encoder.encodeToString(Hex.decode("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"));

        assertEquals(String.format("$argon2id$m=32,t=3,p=4,keyid=%s,data=%s$%s$%s", encoder.encodeToString(secret), encoder.encodeToString(data), encoder.encodeToString(salt), hash), phc.toString());
    }

    @Test
    public void testParsePHC() {
        String[] vectors = {
                "$argon2i$m=120,t=5000,p=2",
                "$argon2i$m=120,t=1294967295,p=2",
                "$argon2i$m=2040,t=5000,p=255",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQ",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0ZQA",
                "$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc",
                "$argon2i$m=120,t=5000,p=2$/LtFjH5rVL8",
                "$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI",
                "$argon2i$m=120,t=5000,p=2$BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI",
                "$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI",
                "$argon2i$m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
                "$argon2i$m=120,t=5000,p=2,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$EkCWX6pSTqWruiR0",
                "$argon2i$m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$iHSDPHzUhPzK7rCcJgOFfg$J4moa2MM0/6uf3HbY2Tf5Fux8JIBTwIhmhxGRbsY14qhTltQt+Vw3b7tcJNEbk8ium8AQfZeD4tabCnNqfkD1g"
        };

        for (int i = 0; i < vectors.length; i++) {
            var phc = PHC.parse(vectors[i]);
            assertEquals(PHCFunction.ARGON2_I, phc.getFunction());
            if (i == 2) {
                assertEquals(Integer.valueOf(2040), phc.getParam(Argon2i.M));
            } else {
                assertEquals(Integer.valueOf(120), phc.getParam(Argon2i.M));
            }
            if (i == 1) {
                assertEquals(Integer.valueOf(1294967295), phc.getParam(Argon2i.T));
            } else {
                assertEquals(Integer.valueOf(5000), phc.getParam(Argon2i.T));
            }
            if (i == 2) {
                assertEquals(Integer.valueOf(255), phc.getParam(Argon2i.P));
            } else {
                assertEquals(Integer.valueOf(2), phc.getParam(Argon2i.P));
            }
            assertEquals(vectors[i], phc.toString());
        }
    }
}
