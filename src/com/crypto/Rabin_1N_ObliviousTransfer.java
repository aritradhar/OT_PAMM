//*************************************************************************************
//*********************************************************************************** *
//author Aritra Dhar 																* *
//Research Engineer																  	* *
//Xerox Research Center India													    * *
//Bangalore, India																    * *
//--------------------------------------------------------------------------------- * * 
///////////////////////////////////////////////// 									* *
//The program will do the following:::: // 											* *
///////////////////////////////////////////////// 									* *
//version 1.0 																		* *
//*********************************************************************************** *
//*************************************************************************************

package com.crypto;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

import sun.security.ec.SunEC;

import org.apache.commons.codec.binary.Base64;


public class Rabin_1N_ObliviousTransfer 
{
	/*
	 * step 1
	 * return n,d,e
	 * server side
	 */
	public static BigInteger[] generateServerKey(int securityParameter) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
		keyPairGen.initialize(securityParameter, secRand);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(keyPair.getPrivate(),RSAPrivateKeySpec.class);
		
		BigInteger N = pub.getModulus();
		BigInteger D = priv.getPrivateExponent();
		BigInteger E = pub.getPublicExponent();
		
		return new BigInteger[]{N, D, E};
	}
	
	/*
	 * step 2
	 * server side
	 */
	public static BigInteger[] generateRandomMsg(int numMsg, int msg_size)
	{
		SecureRandom sec = new SecureRandom();
		byte[][] M = new byte[numMsg][msg_size];
		
		for(int i = 0; i < numMsg; i++)
		{
			sec.nextBytes(M[i]);
		}
		BigInteger[] X = new BigInteger[numMsg];
		
		for(int i = 0; i< numMsg; i++)
		{
			X[i] = new BigInteger(M[i]);
		}
		
		return X;
	}
	
	/*
	 * Step 3
	 * generate v 
	 * client side
	 */
	public static BigInteger generateQuery(int msgCh, BigInteger[] X, BigInteger N, BigInteger E) throws NoSuchAlgorithmException
	{
		if(msgCh > X.length)
			throw new IllegalArgumentException("Value " + msgCh + " is improper");
	
		SecureRandom sec = SecureRandom.getInstance("SHA1PRNG");
		byte[] k = new byte[2];
		sec.nextBytes(k);
		BigInteger K = new BigInteger(k);
		
		return X[msgCh].mod(N).add(K.modPow(E, N)).mod(N); // (Xb + K^e) mod N = (Xb mod N + K^e mod N) mod
		
	}
	
	/*
	 * Step 4 
	 * server side
	 */
	
	public static BigInteger[] sendObliviousEnc(BigInteger V, int numMsg, BigInteger X[], BigInteger D, BigInteger N, BigInteger[] MSG)
	{
		if(X.length != MSG.length)
			throw new IllegalArgumentException("Argument size mismatch");
		
		BigInteger[] Ki = new BigInteger[numMsg];
		BigInteger[] MiP = new BigInteger[numMsg];
		
		for(int i = 0; i < numMsg; i++)
	    {
	    	Ki[i] = V.subtract(X[i]).modPow(D, N);
	    	
	    	MiP[i] = MSG[i].add(Ki[i]);
	    }
		
		return MiP;
	}
	
	/*
	 * Step 4 
	 * final step
	 * decrypt and extract the msg
	 * client side
	 */
	
	public static BigInteger decrypt(int msgCh, BigInteger[] MiP, BigInteger K)
	{	
		return MiP[msgCh].subtract(K);
	}
	
	
	/*////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	 * Test
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, SignatureException, InvalidKeyException 
	{
		Provider sunEC = new SunEC();
        Security.addProvider(sunEC);
		KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", "SunEC");
		kg.initialize(384, new SecureRandom());
		KeyPair kp = kg.genKeyPair();
		PublicKey ec_pk = kp.getPublic();
		PrivateKey ec_sk = kp.getPrivate();
		System.out.println(Base64.encodeBase64URLSafeString(ec_pk.getEncoded()));
		System.out.println(Base64.encodeBase64URLSafeString(ec_sk.getEncoded()));
		
		Signature sig = Signature.getInstance("SHA256withECDSA", "SunEC");
		sig.initSign(ec_sk);
		sig.update((byte) 0x00);
		byte[] signature = sig.sign();
		System.out.println(signature.length);
		
		sig.initVerify(ec_pk);
		sig.update((byte) 0x00);
		System.out.println(sig.verify(signature));
		
		System.out.println("Enter no if messages");
		Scanner s = new Scanner(System.in);
		int MAX = s.nextInt();
		s.close();
		
		long startTime = System.currentTimeMillis();
		
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
		SecureRandom secRand = SecureRandom.getInstance("SHA1PRNG");
		keyPairGen.initialize(1024, secRand);
		KeyPair keyPair = keyPairGen.generateKeyPair();
		
		PrivateKey sk = keyPair.getPrivate();
		PublicKey pk = keyPair.getPublic();
		
		
		KeyFactory fact = KeyFactory.getInstance("RSA");
		RSAPublicKeySpec pub = fact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
		RSAPrivateKeySpec priv = fact.getKeySpec(keyPair.getPrivate(),RSAPrivateKeySpec.class);
		
		BigInteger N = pub.getModulus();
		BigInteger D = priv.getPrivateExponent();
		BigInteger E = pub.getPublicExponent();
		
		SecureRandom sec = SecureRandom.getInstance("SHA1PRNG");
		
		//random messages
		byte[][] M = new byte[MAX][4];
		byte[][] MGen = new byte[MAX][512];
		
		for(int i = 0; i < MAX; i++)
		{
			sec.nextBytes(M[i]);
			sec.nextBytes(MGen[i]);
		}
		
		BigInteger[] X = new BigInteger[MAX];

		BigInteger[] MSG = new BigInteger[MAX];
		
		for(int i = 0; i< MAX; i++)
		{
			X[i] = new BigInteger(M[i]);
			MSG[i] = new BigInteger(MGen[i]);
		}
		
		byte[] k = new byte[2];
		sec.nextBytes(k);
		BigInteger K = new BigInteger(k);
		
	    int msgCh = sec.nextInt(MAX);
		BigInteger V = BigInteger.ZERO;
		
		
	    V = X[msgCh].mod(N).add(K.modPow(E, N)).mod(N); // (Xb + K^e) mod N = (Xb mod N + K^e mod N) mod N
		
	    BigInteger[] Ki = new BigInteger[MAX];
	    BigInteger[] MiP = new BigInteger[MAX];
	    
	    for(int i = 0; i < MAX; i++)
	    {
	    	Ki[i] = V.subtract(X[i]).modPow(D, N);
	    	
	    	MiP[i] = MSG[i].add(Ki[i]);
	    }
		
		//receiver's side
		BigInteger decMsg = MiP[msgCh].subtract(K);
		
		System.out.println("OMSG : " + MSG[msgCh]);
		System.out.println("Msg random bit : " + msgCh);
		System.out.println("DECM : "+decMsg);
		
		long endTime = System.currentTimeMillis();
		
		System.out.println("Total time taken : " + (endTime - startTime) + " ms.");
		
	}
}
