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

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class WriteKey 
{
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException 
	{
		BigInteger[] out = Rabin_1N_ObliviousTransfer.generateServerKey(2048);
		BigInteger N = out[0];
		BigInteger D = out[1];
		BigInteger E = out[2];
		
		FileWriter fwN = new FileWriter("C:\\KeyBase\\N.key");
		FileWriter fwD = new FileWriter("C:\\KeyBase\\D.key");
		FileWriter fwE = new FileWriter("C:\\KeyBase\\E.key");
		
		fwN.append(N.toString());
		fwD.append(D.toString());
		fwE.append(E.toString());
		
		fwN.close();
		fwD.close();
		fwE.close();
	}
}
