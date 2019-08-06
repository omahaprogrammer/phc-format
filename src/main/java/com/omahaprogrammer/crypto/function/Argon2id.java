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

public final class Argon2id extends Argon2<Argon2id> {
    public static final MemorySizeParam<Argon2id> M = MemorySizeParam.getInstance();
    public static final IterationsParam<Argon2id> T = IterationsParam.getInstance();
    public static final ParallelismParam<Argon2id> P = ParallelismParam.getInstance();
    public static final KeyIdParam<Argon2id> KEY_ID = KeyIdParam.getInstance();
    public static final DataParam<Argon2id> DATA = DataParam.getInstance();

    private static final Argon2id INSTANCE = new Argon2id();

    private Argon2id() {
        super("argon2id", Argon2Parameters.ARGON2_id);
    }

    public static Argon2id getInstance() {
        return INSTANCE;
    }
}
