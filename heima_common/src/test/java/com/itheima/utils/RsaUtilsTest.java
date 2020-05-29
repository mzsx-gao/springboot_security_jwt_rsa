package com.itheima.utils;

import org.junit.Test;

import static org.junit.Assert.*;

public class RsaUtilsTest {

    private String privateFilePath = "/Users/gaoshudian/tmp/id_key_rsa";
    private String publicFilePath = "/Users/gaoshudian/tmp/id_key_rsa.pub";

    @Test
    public void generateKey() throws Exception {
        RsaUtils.generateKey(publicFilePath, privateFilePath, "csci", 2048);
    }

    @Test
    public void getPublicKey() throws Exception {
        System.out.println(RsaUtils.getPublicKey(publicFilePath));
    }

    @Test
    public void getPrivateKey() throws Exception {
        System.out.println(RsaUtils.getPrivateKey(privateFilePath));
    }


}