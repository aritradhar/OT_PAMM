package com.test;

import java.math.BigInteger;
import java.util.Random;

import com.crypto.Paillier;

public class TestMain1 
{
	public static void main(String[] args)
	{
		byte[] plain = new byte[8];
		Random rand = new Random();
		rand .nextBytes(plain);
		
		//encoding to bypass 2's complement
		byte[] res = new byte[plain.length + 2];
		res[1] = 0x00;
		System.arraycopy(plain, 0, res, 1, plain.length);
		if(plain[0]<0)
			res[plain.length + 1] = 0x00;
		else
			res[plain.length + 1] = 0x01;
		
		BigInteger b = new BigInteger(res);
		
		
		for(byte i : res)
		{
			System.out.print(i + " ");
		}
		System.out.println();
		Paillier pal = new Paillier();
		
		BigInteger cb = pal.Encryption(b);
		//System.out.println(cb);
		BigInteger dec = pal.Decryption(cb);
		//System.out.println(b);
		//System.out.println(dec);
		
		byte[] c = pal.Encryption(res);
		
		for(byte i : c)
		{
			System.out.print(i + " ");
		}
		System.out.println();
		
		byte[] dp = pal.Decryption(c);
		
		for(byte i : dp)
		{
			System.out.print(i + " ");
		}
		System.out.println();
	}
}
