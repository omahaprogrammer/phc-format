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
