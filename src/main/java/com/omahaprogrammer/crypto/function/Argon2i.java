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

import org.bouncycastle.crypto.params.Argon2Parameters;

public final class Argon2i extends Argon2<Argon2i> {
    public static final MemorySizeParam<Argon2i> M = MemorySizeParam.getInstance();
    public static final IterationsParam<Argon2i> T = IterationsParam.getInstance();
    public static final ParallelismParam<Argon2i> P = ParallelismParam.getInstance();
    public static final KeyIdParam<Argon2i> KEY_ID = KeyIdParam.getInstance();
    public static final DataParam<Argon2i> DATA = DataParam.getInstance();

    private static final Argon2i INSTANCE = new Argon2i();

    private Argon2i() {
        super("argon2i", Argon2Parameters.ARGON2_i);
    }

    /**
     * Provides the singleton instance of this function
     * @return the singleton instance
     */
    public static Argon2i getInstance() {
        return INSTANCE;
    }
}
