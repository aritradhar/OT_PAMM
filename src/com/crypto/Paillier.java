package com.crypto;


import java.math.BigInteger;
import java.util.Random;

public class Paillier {

	private BigInteger p, q, lambda;
	public BigInteger n;
	public BigInteger nsquare;
	private BigInteger g;

	private int bitLength;

	public Paillier(int bitLengthVal, int certainty) {
		KeyGeneration(bitLengthVal, certainty);
	}


	public Paillier() {
		KeyGeneration(1024, 128);
	}


	public void KeyGeneration(int bitLengthVal, int certainty) {
		bitLength = bitLengthVal;
	
		p = new BigInteger(bitLength / 2, certainty, new Random());
		q = new BigInteger(bitLength / 2, certainty, new Random());

		n = p.multiply(q);
		nsquare = n.multiply(n);

		g = new BigInteger(n.bitLength(), new Random());
		lambda = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)).divide(
				p.subtract(BigInteger.ONE).gcd(q.subtract(BigInteger.ONE)));
		
		//System.out.println("g :: " + g);
		if (g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).gcd(n).intValue() != 1) {
			System.out.println("g is not good. Choose g again.");
			System.exit(1);
		}
	}

	public BigInteger Encryption(BigInteger m, BigInteger r) {
		return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);
	}

	public BigInteger Encryption(BigInteger m) {
		BigInteger r = new BigInteger(bitLength, new Random());
		return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare);

	}
	
	public byte[] Encryption(byte[] byteArray)
	{
		BigInteger r = new BigInteger(bitLength, new Random());
		BigInteger m = new BigInteger(byteArray);
		return g.modPow(m, nsquare).multiply(r.modPow(n, nsquare)).mod(nsquare).toByteArray();
	}


	public BigInteger Decryption(BigInteger c) {
		BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
		return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n);
	}
	
	public byte[] Decryption(byte[] byteArray)
	{
		BigInteger u = g.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).modInverse(n);
		BigInteger c = new BigInteger(byteArray);
		return c.modPow(lambda, nsquare).subtract(BigInteger.ONE).divide(n).multiply(u).mod(n).toByteArray();
	}
	
	
	public static BigInteger stringToBigInteger(String st)
	{
		return new BigInteger(st.getBytes());
	}
	
	public static String bigIntegerToString(BigInteger bi)
	{
		return new String(bi.toByteArray());
	}

	public static void main(String[] str) {

		Paillier paillier = new Paillier();

		BigInteger m1 = new BigInteger("20");
		BigInteger m2 = new BigInteger("60");
		
		/* encryption*/
		BigInteger em1 = paillier.Encryption(m1);
		BigInteger em2 = paillier.Encryption(m2);
		/* printout encrypted text*/
		System.out.println(em1);
		System.out.println(em2);
		/* printout decrypted text */
		System.out.println(paillier.Decryption(em1).toString());
		System.out.println(paillier.Decryption(em2).toString());

		BigInteger temp = stringToBigInteger("Aritra");
		BigInteger bi = paillier.Encryption(temp);
		System.out.println(temp);
		System.out.println(bi);
		
		BigInteger bii = paillier.Decryption(bi);
		System.out.println(bigIntegerToString(bii));
		
		/* test homomorphic properties -> D(E(m1)*E(m2) mod n^2) = (m1 + m2) mod n */
		BigInteger product_em1em2 = em1.multiply(em2).mod(paillier.nsquare);
		BigInteger sum_m1m2 = m1.add(m2).mod(paillier.n);
		System.out.println("original sum: " + sum_m1m2.toString());
		System.out.println("decrypted sum: " + paillier.Decryption(product_em1em2).toString());

		/* test homomorphic properties -> D(E(m1)^m2 mod n^2) = (m1*m2) mod n */
		BigInteger expo_em1m2 = em1.modPow(m2, paillier.nsquare);
		BigInteger prod_m1m2 = m1.multiply(m2).mod(paillier.n);
		System.out.println("original product: " + prod_m1m2.toString());
		System.out.println("decrypted product: " + paillier.Decryption(expo_em1m2).toString());

	}
}
