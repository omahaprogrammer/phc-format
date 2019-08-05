package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2d extends Argon2<Argon2d> {
    public static final MemorySizeParam<Argon2d> M = MemorySizeParam.getInstance();
    public static final IterationsParam<Argon2d> T = IterationsParam.getInstance();
    public static final ParallelismParam<Argon2d> P = ParallelismParam.getInstance();
    public static final KeyIdParam<Argon2d> KEY_ID = KeyIdParam.getInstance();
    public static final DataParam<Argon2d> DATA = DataParam.getInstance();
    public static final HashLengthParam<Argon2d> LENGTH = HashLengthParam.getInstance();

    Argon2d() {
        super("argon2d", Argon2Parameters.ARGON2_d);
    }
}

