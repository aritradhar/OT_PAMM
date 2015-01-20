package com.crypto;
import java.math.BigInteger;
import java.util.Random;


public class SafePrime 
{
	public static void main(String[] args) 
	{
		
		long start = System.currentTimeMillis();
		
		int tryc = 0;
		
		while(true)
		{
			tryc++;
				
			BigInteger p = new BigInteger(512, 64, new Random());
			long end = System.currentTimeMillis();
			
			if(tryc == 1)
				System.out.println("Prime found in " + (end - start) + " ms.");
			
			BigInteger q = new BigInteger("2").multiply(p).add(BigInteger.ONE);
			
			if(tryc%100 == 0)
				System.out.println(tryc);
			
			if(q.isProbablePrime(64))
			{
				System.out.println(p);
				System.out.println(q);
				
				System.out.println("Total try : " + tryc);
				break;
			}
		}
		
		long end = System.currentTimeMillis();
		
		System.out.println("Total execution time : " + (end - start) + " ms.");
	}
}
