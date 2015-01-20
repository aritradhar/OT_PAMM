package com.test;


import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;

import com.crypto.Paillier;

public class TestMain 
{
	public static void main(String[] args) throws IOException 
	{
		Paillier paillier = new Paillier();
		
		File fi = new File("C:\\Users\\w4j3yyfd\\Desktop\\index.jpg");
		byte[] fileContent = Files.readAllBytes(fi.toPath());

		int i = 0;
		for(i = 0; i< fileContent.length; i++)
		{
			System.out.print(fileContent[i] + " ");
		}
		System.out.println();
		System.out.println(i);
		i = 0;
		//byte[] tmp = Arrays.copyOfRange(fileContent, 0, 10);
		//System.out.println(new BigInteger(fileContent));
		
		for(i = 0; i< new BigInteger(fileContent).toByteArray().length; i++)
		{
			System.out.print(new BigInteger(fileContent).toByteArray()[i] + " ");
		}
		
		System.out.println();
		System.out.println(i);
		
		byte[] cipherFileContent = paillier.Encryption(fileContent);
		//System.out.println(new BigInteger(cipherFileContent));
		
		OutputStream out = null;
		try 
		{
		    out = new BufferedOutputStream(new FileOutputStream("C:\\Users\\w4j3yyfd\\Desktop\\enc.jpg"));
		    out.write(cipherFileContent);
		    System.out.println("Encrypted file is written in the disk");
		} 
		finally 
		{
		    if (out != null)
		    	out.close();
		}
		
		OutputStream out1 = null;
		
		byte[] decryptedFileContent = paillier.Decryption(cipherFileContent);
		
		for(i = 0; i< decryptedFileContent.length; i++)
		{
			System.out.print(decryptedFileContent[i] + " ");
		}
		System.out.println();
		System.out.println(i);
		//System.out.println(new BigInteger(decryptedFileContent));
		
		try 
		{
		    out1 = new BufferedOutputStream(new FileOutputStream("C:\\Users\\w4j3yyfd\\Desktop\\dec.jpg"));
		    out.write(decryptedFileContent);
		    System.out.println("Decrypted file is written in the disk");
		} 
		finally 
		{
		    if (out1 != null)
		    	out1.close();	    	    
		}
	}
}
