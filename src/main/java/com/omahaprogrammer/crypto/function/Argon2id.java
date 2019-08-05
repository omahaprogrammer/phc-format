package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2id extends Argon2<Argon2id> {
    public static final MemorySizeParam<Argon2id> M = MemorySizeParam.getInstance();
    public static final IterationsParam<Argon2id> T = IterationsParam.getInstance();
    public static final ParallelismParam<Argon2id> P = ParallelismParam.getInstance();
    public static final KeyIdParam<Argon2id> KEY_ID = KeyIdParam.getInstance();
    public static final DataParam<Argon2id> DATA = DataParam.getInstance();
    public static final HashLengthParam<Argon2id> LENGTH = HashLengthParam.getInstance();

    Argon2id() {
        super("argon2id", Argon2Parameters.ARGON2_id);
    }
}
