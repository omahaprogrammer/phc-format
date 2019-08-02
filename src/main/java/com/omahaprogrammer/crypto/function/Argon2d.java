package com.omahaprogrammer.crypto.function;

import org.bouncycastle.crypto.params.Argon2Parameters;

public class Argon2d extends Argon2<Argon2d> {
    public final Argon2d INSTANCE = new Argon2d();

    private Argon2d() {
        super("argon2d", Argon2Parameters.ARGON2_d);
    }
}

