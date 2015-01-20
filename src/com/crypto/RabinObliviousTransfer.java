package com.crypto;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class RabinObliviousTransfer 
{
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException 
	{
		long startTime = System.currentTimeMillis();
		
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("rsa");
		SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
		keyPairGen.initialize(2048, secRand);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		
		PrivateKey sk = keyPair.getPrivate();
		PublicKey pk = keyPair.getPublic();
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(keyPair.getPrivate(),RSAPrivateKeySpec.class);
		
		BigInteger N = pub.getModulus();
		BigInteger D = priv.getPrivateExponent();
		BigInteger E = pub.getPublicExponent();
		
		SecureRandom sec = new SecureRandom();
		
		//random messages
		byte[] M0 = new byte[512];
		byte[] M1 = new byte[512];
		byte[] M2 = new byte[512];
		byte[] M3 = new byte[512];
		
		sec.nextBytes(M0);
		sec.nextBytes(M1);
		sec.nextBytes(M2);
		sec.nextBytes(M3);
		
		BigInteger X0 = new BigInteger(M0);
		BigInteger X1 = new BigInteger(M1);

		BigInteger MSG0 = new BigInteger(M2);
		BigInteger MSG1 = new BigInteger(M3);
		
		System.out.println("MSG0 : " + MSG0);
		System.out.println("MSG1 : " + MSG1);
		
		byte[] k = new byte[2];
		sec.nextBytes(k);
		BigInteger K = new BigInteger(k);
		
		//chosen 1
		boolean msgCh = sec.nextBoolean();
		BigInteger V = BigInteger.ZERO;
		
		if(msgCh)
			V = X1.mod(N).add(K.modPow(E, N)).mod(N); // (Xb + K^e) mod N = (Xb mod N + K^e mod N) mod N
		else
			V = X0.mod(N).add(K.modPow(E, N)).mod(N);
		
		BigInteger K0 = V.subtract(X0).modPow(D, N);
		BigInteger K1 = V.subtract(X1).modPow(D, N);
		
		BigInteger M0P = MSG0.add(K0);
		BigInteger M1P = MSG1.add(K1);
		
		//receiver's side
		BigInteger decMsg = BigInteger.ZERO;
		
		if(msgCh)
			decMsg = M1P.subtract(K1);
		else
			decMsg = M0P.subtract(K0);
		
		System.out.println("Msg random bit : " + msgCh);
		System.out.println("DECM : "+decMsg);
		
		long endTime = System.currentTimeMillis();
		
		System.out.println("Total time taken : " + (endTime - startTime) + " ms.");
		
	}
}
