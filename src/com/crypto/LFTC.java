package com.crypto;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;


public class LFTC 
{
	
	public BigInteger n;
	public BigInteger t;
	public BigInteger g;
	public BigInteger h;

	/*
	 * length fixable
	 */
	public int s;
	//private key
	public BigInteger alpha;
	/*
	 * Ls((n + 1)^m mod n^(s + 1)) = m mod (n^s)
	 */
	public static BigInteger LS(BigInteger n, BigInteger m, Integer s)
	{
		return m.mod(n.pow(s));
	}
	
	/*
	 * constructor to set the security parameter
	 * Set the r for which m in Z_(n^s)
	 * In case the certainty is not set it will fall-back to 64
	 */
	public LFTC(int securityParameter, int s)
	{
		this.s = s;
		this.makeKey(securityParameter, 64);
	}
	
	public LFTC(int securityParameter, int primeCertainty, int s)
	{
		this.s = s;
		this.makeKey(securityParameter, primeCertainty);
	}
	
	/*
	 * Return RSA p and q such that p = 2p' + 1 and q = 2q' + 1 
	 * both p' and q' are also primes
	 */
	public BigInteger[] makeKey(int securityParameter, int parimeCertainty)
	{
		BigInteger p,q, pPrime, qPrime = BigInteger.ZERO;
		
		while(true)
		{
			pPrime = new BigInteger(securityParameter, parimeCertainty, new SecureRandom());
			p = pPrime.multiply(new BigInteger("2")).add(BigInteger.ONE);
			
			if(p.isProbablePrime(parimeCertainty))
				break;
		}
		
		while(true)
		{
			qPrime = new BigInteger(securityParameter, parimeCertainty, new SecureRandom());
			q = pPrime.multiply(new BigInteger("2")).add(BigInteger.ONE);
			
			if(q.isProbablePrime(parimeCertainty))
				break;
		}
		
		this.n = p.multiply(q);
		this.t = pPrime.multiply(qPrime);
		
		BigInteger[] toReturn ={p, pPrime, q, qPrime};
		
		this.makePublicComponets();
		this.makePrivateComponets();
		
		System.out.println("Key calculation done.");
		return toReturn;
	}
	
	/*
	 * public key in the form (n,g,h)
	 */
	
	public void makePublicComponets()
	{
		this.g = new BigInteger(n.bitLength(), new SecureRandom());
		//this.g = this.g.multiply(this.g);
	}
	
	/*
	 * private components
	 * For the mean time keep the alpha here
	 * later write a destructor to safely kill all private componets
	 */
	public void makePrivateComponets()
	{
		this.alpha = new BigInteger(t.bitLength(), new Random());
		this.h = g.modPow(alpha, n);
	}
	
	/*
	 * Returns an array in form c= (G,H)
	 */
	public BigInteger[] Encryption(BigInteger message)
	{
		BigInteger r = new BigInteger(n.bitCount(), new Random());
		
		BigInteger nps = n.pow(s + 1);
		
		BigInteger G = g.modPow(r, this.n);
		BigInteger H = h.modPow(r, this.n).modPow(n.pow(s), nps).multiply(n).add(BigInteger.ONE).modPow(message, nps).mod(nps);
		
		BigInteger[] toReturn = {G, H};
		return toReturn;
		
	}
	
	public BigInteger Decryption(BigInteger[] cipherText)
	{
		BigInteger G = cipherText[0];
		BigInteger H = cipherText[1];
		
		BigInteger tmp = H.multiply(G.modPow(alpha, n));
		
		return null;
	}
	
	public static void main(String[] args) 
	{
		LFTC cipher = new LFTC(512, 100);
		
		BigInteger[] en = cipher.Encryption(new BigInteger("1"));
		
		System.out.println(en[0]);
		System.out.println(en[1]);
		
		System.out.println("Done ..");
	}
}
