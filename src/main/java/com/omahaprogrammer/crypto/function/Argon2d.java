package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public final class Argon2d extends Argon2<Argon2d> {
    public static final MemorySizeParam<Argon2d> M = MemorySizeParam.getInstance();
    public static final IterationsParam<Argon2d> T = IterationsParam.getInstance();
    public static final ParallelismParam<Argon2d> P = ParallelismParam.getInstance();
    public static final KeyIdParam<Argon2d> KEY_ID = KeyIdParam.getInstance();
    public static final DataParam<Argon2d> DATA = DataParam.getInstance();

    private static final Argon2d INSTANCE = new Argon2d();

    private Argon2d() {
        super("argon2d", Argon2Parameters.ARGON2_d);
    }

    public static Argon2d getInstance() {
        return INSTANCE;
    }
}

