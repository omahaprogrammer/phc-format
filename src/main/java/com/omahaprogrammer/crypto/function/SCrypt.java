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

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class SCrypt extends PHCFunction<SCrypt> {
    private static final Map<String, Param<SCrypt, ?>> params = new HashMap<>();
    private static final int DEFAULT_SALT_LENGTH = 128;
    private static final int DEFAULT_HASH_LENGTH = 64;
    private static final SCrypt INSTANCE = new SCrypt();

    public static final CostFactorParam N = new CostFactorParam();
    public static final BlockSizeParam R = new BlockSizeParam();
    public static final ParallelizationParameter P = new ParallelizationParameter();

    public static SCrypt getInstance() {
        return INSTANCE;
    }

    /**
     * Creates a new function object
     */
    private SCrypt() {
        super("scrypt");
    }

    @Override
    @SuppressWarnings("unchecked")
    public <V> Optional<Param<SCrypt, V>> getParam(String paramId) {
        return Optional.ofNullable((Param<SCrypt, V>) params.get(paramId));
    }

    @Override
    public byte[] protectPassword(Map<Param<SCrypt, ?>, ?> params, byte[] salt, char[] password, int length) {
        if (!params.keySet().containsAll(Set.of(N, R, P))) {
            throw new IllegalArgumentException("Required parameters missing");
        }
        CharBuffer charBuffer = CharBuffer.wrap(password);
        ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
        byte[] pwdBytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
        byteBuffer.clear();
        while (byteBuffer.hasRemaining()) {
            byteBuffer.put((byte)0);
        }
        try {
            return org.bouncycastle.crypto.generators.SCrypt.generate(pwdBytes, salt, N.getValue(params), R.getValue(params), P.getValue(params), length);
        } finally {
            Arrays.fill(pwdBytes, (byte) 0);
        }
    }

    @Override
    public int getDefaultSaltLength() {
        return DEFAULT_SALT_LENGTH;
    }

    @Override
    public int getDefaultHashLength() {
        return DEFAULT_HASH_LENGTH;
    }

    /**
     * This class describes a parameter whose value represents the cost value for the function.
     */
    public static final class CostFactorParam extends Param<SCrypt, Integer> {
        private CostFactorParam() {
            super("N", 1, Integer.class);
            params.put("N", this);
        }

        protected void validateImpl(Integer value) {
            if (value <= 1 || value >= 32) {
                throw new IllegalArgumentException("Cost factor must be greater than 1 and less than 32");
            }
        }
    }

    /**
     * This class describes a parameter whose value represents the block size multiple for the
     * function. The block size will be 128 bytes multiplied by the value associated with this
     * parameter.
     */
    public static final class BlockSizeParam extends Param<SCrypt, Integer> {
        private BlockSizeParam() {
            super("r", 2, Integer.class);
            params.put("r", this);
        }

        protected void validateImpl(Integer value) {
            if (value <= 0) {
                throw new IllegalArgumentException("Value must be greater than or equal to 1");
            }
        }
    }

    /**
     * This class describes a parameter whose value represents the parallelization factor
     * for this function.
     */
    public static final class ParallelizationParameter extends Param<SCrypt, Integer> {
        private ParallelizationParameter() {
            super("p", 3, Integer.class);
            params.put("p", this);
        }

        @Override
        protected void validateImpl(Integer value) {
            if (value <= 0) {
                throw new IllegalArgumentException("Value must be greater than or equal to 1");
            }
        }
    }
}
