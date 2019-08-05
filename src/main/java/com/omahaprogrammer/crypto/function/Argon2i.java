package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2i extends Argon2<Argon2i> {
    public static final MemorySizeParam<Argon2i> M = MemorySizeParam.getInstance();
    public static final IterationsParam<Argon2i> T = IterationsParam.getInstance();
    public static final ParallelismParam<Argon2i> P = ParallelismParam.getInstance();
    public static final KeyIdParam<Argon2i> KEY_ID = KeyIdParam.getInstance();
    public static final DataParam<Argon2i> DATA = DataParam.getInstance();
    public static final HashLengthParam<Argon2i> LENGTH = HashLengthParam.getInstance();

    Argon2i() {
        super("argon2i", Argon2Parameters.ARGON2_i);
    }
}
