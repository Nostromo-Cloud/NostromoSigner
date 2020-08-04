package com.nostromo.api.signer;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

public interface ISigner {

    KeyPair generateKeyPair() throws NoSuchAlgorithmException;
    byte[] encrypt(byte[] plainText, PublicKey publicKey) throws NoSuchAlgorithmException , NoSuchPaddingException , InvalidKeyException , IllegalBlockSizeException , BadPaddingException;
    byte[] decrypt(byte[] cipherText, PrivateKey privateKey) throws NoSuchAlgorithmException , NoSuchPaddingException , InvalidKeyException, IllegalBlockSizeException , BadPaddingException;
    byte[] sign(byte[] plainText, PrivateKey privateKey) throws NoSuchAlgorithmException , InvalidKeyException , SignatureException;
    boolean verify(byte[] plainText, String signature, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException;
    PublicKey get(String filename) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException;
}
