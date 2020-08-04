package com.nostromo.main;

import com.nostromo.api.signer.ISigner;
import com.nostromo.main.signer.Signer;

public class NostromoSigner {
    private static final ISigner signer = new Signer();

    public static ISigner getSigner() {
        return signer;
    }
}
