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
import java.security.SecureRandom;
import java.util.Random;

import com.util.*;

public class ClientCryptEngine 
{
	private int securityParameter, certainty;
	private int s;
	private BigInteger n, d;
	private BigInteger msg;

	public ClientCryptEngine(BigInteger n)
	{
		this.n = n;
	}

	//constructor for generator's side
	public ClientCryptEngine(int securityParameter, BigInteger msg)
	{
		this.securityParameter = securityParameter;
		this.certainty = 128;
		this.msg = msg;

		this.generateParameters();
	}
	//constructor for generator's side
	public ClientCryptEngine(int securityParameter, int certainty, BigInteger msg)
	{
		this.securityParameter = securityParameter;
		this.certainty = certainty;
		this.msg = msg;

		this.generateParameters();
	}

	/*
	 * Constructor for encryption side
	 * need other side's public key and the message
	 * 
	 */
	public ClientCryptEngine(BigInteger n, BigInteger msg)
	{
		this.n = n;
		this.msg = msg;

		int l = this.msg.bitLength();
		int nBitLength = this.n.bitLength();

		/*
		 * If the size is specified use s as specified 
		 * else assume the message is a string of bits 
		 * of length l, find the smallest s such that 2^l<n^s 
		 */
		this.s = 0;
		while(true)
		{
			this.s++;
			if(this.s * nBitLength > l)
				break;
		}
	}

	/*
	 * Must for destroying all the private information securely
	 */
	public void destroy()
	{
		this.n = null;
		this.d = null;
		this.msg = null;

		System.gc();
	}

	public void setMessage(BigInteger msg)
	{
		this.msg = msg;
		int l = this.msg.bitLength();
		int nBitLength = this.n.bitLength();

		/*
		 * If the size is specified use s as specified 
		 * else assume the message is a string of bits 
		 * of length l, find the smallest s such that 2^l<n^s 
		 */
		this.s = 0;
		while(true)
		{
			this.s++;
			if(this.s * nBitLength > l)
				break;
		}	
	}

	public BigInteger getPublic()
	{
		return this. n;
	}

	public BigInteger getPrivate()
	{
		return this.d;
	}

	public void setPublic(BigInteger d)
	{
		this.d = d;
	}

	public void setPrivate(BigInteger n)
	{
		this.n = n;
	}

	public int getS()
	{
		return this.s;
	}

	public static BigInteger Algorithm1(int s, BigInteger a, BigInteger n)
	{
		BigInteger i = BigInteger.ZERO;

		for(int j = 1; j <= s; j++)
		{
			BigInteger t1 = Utils.L(a.mod(n.pow(j + 1)), n);
			BigInteger t2 = i;

			BigInteger nj = n.pow(j);

			for(int k = 2; k <= j; k++)
			{
				i = i.subtract(BigInteger.ONE);
				t2 = t2.multiply(i.mod(nj));

				BigInteger temp = (t2.multiply(n.pow(k - 1)).divide(new BigInteger(new Integer(Utils.factorial(k)).toString())));
				t1 = t1.subtract(temp).mod(nj);
			}

			i = t1;
		}

		return i;
	}

	public void generateParameters()
	{	
		/*
		 * generates RSA factors
		 */
		BigInteger p = new BigInteger(securityParameter /2, certainty, new SecureRandom());
		BigInteger q = new BigInteger(securityParameter /2, certainty, new SecureRandom());

		//public parameter set
		this.n = p.multiply(q);
		//System.out.println("n " + n.bitLength());

		BigInteger lambda = Utils.lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE));

		if(this.msg != null)
		{
			int l = this.msg.bitLength();
			int nBitLength = this.n.bitLength();

			/*
			 * If the size is specified use s as specified 
			 * else assume the message is a string of bits 
			 * of length l, find the smallest s such that 2^l<n^s 
			 */
			this.s = 0;
			while(true)
			{
				this.s++;
				if(this.s * nBitLength > l)
					break;
			}
		}
		//		System.out.println("Comp :" + new BigInteger("2").pow(l).compareTo(n.pow(s)));
		//		System.out.println("s " + s);
		//		System.out.println("l " + l);


		//private parameter set
		//got this from pre-solved Chinese remainder theorem
		BigInteger lambda_ns = lambda.multiply(n.pow(this.s));
		BigInteger tmp = lambda.multiply(lambda.modInverse(n.pow(this.s))); 
		this.d = tmp.mod(lambda_ns);

		//		System.out.println("n : " + this.n);
		//		System.out.println("d : " + this.d);
	}

	public BigInteger Encrypt()
	{
		BigInteger r = Utils.chooseRandomFromZnStar(this.n);

		BigInteger temp1 = (this.n.add(BigInteger.ONE)).modPow(this.msg, this.n.pow(this.s + 1));
		BigInteger temp2 = r.modPow(this.n.pow(this.s), this.n.pow(this.s + 1));

		/*
		Alternate from the paper
		 */

		/*		int j = 3;
		BigInteger g = (((this.n.add(BigInteger.ONE)).pow(j)).multiply(new BigInteger("19"))).mod(n.pow(this.s + 1));
		BigInteger temp3 = g.modPow(this.msg, this.n.pow(this.s + 1));
		BigInteger temp4 = (temp2.multiply(temp3)).mod(this.n.pow(this.s + 1));
		return temp4;
		 */		////////////////////////

		return (temp1.multiply(temp2)).mod(n.pow(s + 1)); 
	}

	public BigInteger Encrypt(int s)
	{
		BigInteger r = Utils.chooseRandomFromZnStar(this.n);

		BigInteger temp1 = (this.n.add(BigInteger.ONE)).modPow(this.msg, this.n.pow(s + 1));
		BigInteger temp2 = r.modPow(this.n.pow(s), this.n.pow(s + 1));

		return (temp1.multiply(temp2)).mod(n.pow(s + 1)); 
	}

	public BigInteger Encrypt(int s, BigInteger msg)
	{
		BigInteger r = Utils.chooseRandomFromZnStar(this.n);

		BigInteger temp1 = (this.n.add(BigInteger.ONE)).modPow(msg, this.n.pow(s + 1));
		BigInteger temp2 = r.modPow(this.n.pow(s), this.n.pow(s + 1));

		return (temp1.multiply(temp2)).mod(n.pow(s + 1)); 
	}

	/*
	 * Decryption does not require loading any data
	 */
	public BigInteger Decrypt(BigInteger cipherText, int s, BigInteger d, BigInteger n)
	{
		//System.out.println("dec s " + s);
		BigInteger a = cipherText.modPow(d, n.pow(s + 1));

		BigInteger dec = ClientCryptEngine.Algorithm1(s, a, n);
		return dec;
	}

	@SuppressWarnings("unused")
	public static void main(String[] args) 
	{
		int sz = 128, it = 1000, securityParameter = 1024;

		BigInteger msg = new BigInteger(sz, new Random());		
		System.out.println(msg);

		ClientCryptEngine CCE = new ClientCryptEngine(securityParameter, msg);
		//		System.out.println(CCE.getS());
		//		System.out.println(CCE.getPublic().pow(CCE.getS()));
		//		
		//		System.out.println(msg.gcd(CCE.getPublic().pow(CCE.getS())));

		BigInteger cipherText = CCE.Encrypt();
		BigInteger plaintext = CCE.Decrypt(cipherText, CCE.s, CCE.getPrivate(), CCE.getPublic());
		System.out.println(cipherText);

		System.out.println(plaintext);

		/*
		 * 
		for(int i = 0; i< cipherText.toByteArray().length; i++)
		{
			System.out.print(cipherText.toByteArray()[i] + ",");
		}
		System.out.println();
		 */

		/*
		 * Speed test
		 */
		long start = 0, start1 = 0, encTotal = 0, decTotal = 0, startKeyGen = 0, keyGenTot = 0;
		int decBits = 0;
		int correct = 0, wrong = 0;
		for(int i = 0 ; i< it; i++)
		{
			//msg = new BigInteger(sz, new Random());	
			startKeyGen = System.currentTimeMillis();
			ClientCryptEngine C = new ClientCryptEngine(securityParameter, msg);
			keyGenTot += System.currentTimeMillis() - startKeyGen;
			start = System.currentTimeMillis(); 
			BigInteger en = C.Encrypt();
			encTotal += System.currentTimeMillis() - start;
			start1 = System.currentTimeMillis();
			BigInteger plain = C.Decrypt(en, C.s, C.d, C.n);
			//System.out.println(msg.gcd(C.n.pow(C.s)));
			decTotal += System.currentTimeMillis() - start1;
			decBits += plain.bitLength();

			if(plain.compareTo(msg) != 0)
				wrong++;

			else
				correct++;
		}
		long end = System.currentTimeMillis();


		System.out.println("Total correct : " + correct);
		System.out.println("Total wrong : " + wrong);

		try
		{
			System.out.println("Avg " + securityParameter + " bit keyGen time : " + (keyGenTot/it) + " ms.");
			System.out.println("Encryption speed : " + (sz*it)/(encTotal) + " kbps");
			System.out.println("Decryption speed : " + (decBits)/(decTotal) + " kbps");
		}
		catch(Exception ex)
		{
			System.err.println("Increase round");
		}
		/*
		 * Checking homomorphic property
		 */
		BigInteger m1 = new BigInteger("200");
		ClientCryptEngine HPE1 = new ClientCryptEngine(securityParameter, m1);
		BigInteger c1 = HPE1.Encrypt();

		HPE1.setMessage(new BigInteger("100"));
		BigInteger c2 = HPE1.Encrypt();

		BigInteger c3 = c1.multiply(c2);
		BigInteger p = HPE1.Decrypt(c3, HPE1.s, HPE1.d, HPE1.n);

		System.out.println(p);
		/*
		long start = System.currentTimeMillis();
		for(int i = 0 ; i< it; i++)
		{
			CCE.Encrypt(msg);
		}
		long end = System.currentTimeMillis();

		System.out.println("speed : " + (sz*it)/(end - start) + " kbps");
		 */

		//System.out.println(ciphertext);
	}
}
