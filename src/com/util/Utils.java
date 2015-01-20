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

package com.util;

import java.math.BigInteger;
import java.util.Random;

public class Utils 
{
	public static BigInteger lcm(BigInteger a, BigInteger b)
	{
		return (a.multiply(b)).divide(a.gcd(b));
	}
	
	public static BigInteger L(BigInteger x, BigInteger n)
	{
		return (x.subtract(BigInteger.ONE)).divide(n);
	}
	
	public static BigInteger chooseRandomFromZnStar(BigInteger n)
	{
		BigInteger probableCandidate = BigInteger.ONE;
		
		while(true)
		{
			probableCandidate = new BigInteger(n.bitLength(), new Random());
			
			if(probableCandidate.gcd(n).intValue() == 1 && probableCandidate.compareTo(n) == -1)
				break;
		}
		
		return probableCandidate;
	}
	
	public static BigInteger stringToBigInteger(String st)
	{
		return new BigInteger(st.getBytes());
	}
	
	public static String bigIntegerToString(BigInteger bi)
	{
		return new String(bi.toByteArray());
	}
	
	public static byte[] fixArrayForBigInt(byte[] input)
	{
		byte[] res = new byte[input.length + 2];
		res[0] = 0x00;
		System.arraycopy(input, 0, res, 1, input.length);
		if(input[0]<0)
			res[input.length + 1] = 0x00;
		else
			res[input.length + 1] = 0x01;
		
		return res;
	}
	
	public static byte[] normalizeArray(byte[] input)
	{
		byte endPoint = input[input.length - 1];
		
		if(endPoint == 1)
		{
			byte[] toReturn = new byte[input.length - 1];
			System.arraycopy(input, 0, toReturn, 0, input.length - 1);
			return toReturn;
		}
		
		else
		{
			byte[] toReturn = new byte[input.length - 2];
			System.arraycopy(input, 1, toReturn, 0, input.length - 1);
			return toReturn;
		}
	}
	
	public static int factorial(int n)
	{
		if(n == 0 || n == 1)
			return 1;
		
		int fact = 1;
		
		for(int i = 1; i<=n; i++)
		{
			fact *= i;
		}
		
		return fact;
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
				
				BigInteger temp = (t2.multiply(n.pow(k - 1)).divide(new BigInteger(new Integer(Utils.factorial(k)).toString()))).mod(nj);
				t1 = t1.subtract(temp);
			}
			
			i = t1;
		}
		
		return i;
	}
	
	public static String bitString(int bitlen, int num)
	{
		String out = Integer.toBinaryString(num);
		int numBits = out.length();
		if(numBits > bitlen)
			throw new IllegalArgumentException("bitlen " + bitlen + " is less than bits in " + num );
		
		else if (numBits < bitlen)
		{
			int paddLen = bitlen - numBits;
			StringBuffer str = new StringBuffer("");
			for(int i = 0; i < paddLen; i++)
			{
				str = str.append("0");
			}
			str = str.append(out);
			
			return str.toString();
		}
		
		else
			return out;
	}
}
