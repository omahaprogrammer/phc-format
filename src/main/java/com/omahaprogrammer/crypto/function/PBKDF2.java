/*
 * Copyright 2019 Jonathan Paz <omahaprogrammer@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.omahaprogrammer.crypto.function;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class PBKDF2 extends PHCFunction<PBKDF2> {
    private static final Map<String, Param<PBKDF2, ?>> params = new HashMap<>();

    private static final int DEFAULT_SALT_LENGTH = 128;
    private static final int DEFAULT_HASH_LENGTH = 64;

    public static final AlgorithmParam ALG = new AlgorithmParam();
    public static final IterationsParam C = new IterationsParam();

    private static final PBKDF2 INSTANCE = new PBKDF2();

    private PBKDF2() {
        super("pbkdf2");
    }

    public static PBKDF2 getInstance() {
        return INSTANCE;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V> Optional<Param<PBKDF2, V>> getParam(String string) {
        return Optional.ofNullable((Param<PBKDF2, V>)params.get(string));
    }

    @Override
    public int getDefaultSaltLength() {
        return DEFAULT_SALT_LENGTH;
    }

    @Override
    public int getDefaultHashLength() {
        return DEFAULT_HASH_LENGTH;
    }

    @Override
    public byte[] hashPassword(Map<Param<PBKDF2, ?>, ?> params, byte[] salt, char[] password, int length) {
        if (!params.keySet().containsAll(Set.of(ALG, C))) {
            throw new IllegalArgumentException("Required parameters missing");
        }
        var alg = ALG.getValue(params);
        var iterations = C.getValue(params);
        var spec = new PBEKeySpec(password, salt, iterations, length * 8);
        try {
            var fac = SecretKeyFactory.getInstance(String.format("PBKDF2With%s", alg.getLabel()), new BouncyCastleProvider());
            var hash = fac.generateSecret(spec);
            spec.clearPassword();
            return hash.getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    public enum Algorithm {
        HMAC_SHA1("HmacSHA1"),
        HMAC_SHA224("HmacSHA224"),
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA384("HmacSHA384"),
        HMAC_SHA512("HmacSHA512"),
        HMAC_SHA3_224("HmacSHA3-224"),
        HMAC_SHA3_256("HmacSHA3-256"),
        HMAC_SHA3_384("HmacSHA3-384"),
        HMAC_SHA3_512("HmacSHA3-512");

        private final String label;

        Algorithm(String label) {
            this.label = label;
        }

        public String getLabel() {
            return label;
        }

        @Override
        public String toString() {
            return label;
        }
    }

    public static final class AlgorithmParam extends Param<PBKDF2, Algorithm> {
        private AlgorithmParam() {
            super("alg", 1, Algorithm.class);
            params.put("alg", this);
        }

        @Override
        public Algorithm validate(Object obj) {
            if (obj instanceof Algorithm) {
                return super.validate(obj);
            } else if (obj instanceof String) {
                for (var alg : Algorithm.values()) {
                    if (alg.getLabel().equals(obj)) {
                        return super.validate(alg);
                    }
                }
            }
            throw new IllegalArgumentException();
        }

        @Override
        protected void validateImpl(Algorithm value) {
            // no implementation
        }
    }

    public static final class IterationsParam extends Param<PBKDF2, Integer> {
        private IterationsParam() {
            super("c", 2, Integer.class);
            params.put("c", this);
        }

        protected void validateImpl(Integer val) {
            if (val < 1) {
                throw new IllegalArgumentException();
            }
        }
    }
}
