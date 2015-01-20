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


package com.keyGen;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

import org.apache.commons.codec.binary.Base64;

public class SymmetricKeytGen 
{
	int counter;
	String imageDBPath;
	//file name and AES key in bytes
	HashMap<String, byte[]> imageKeyMap;
	//filename and encryption of the file in bytes
	HashMap<String, byte[]> encImgMap;
	//file name and key in Base64 String mode
	HashMap<String, String> imageKeyBase64Map;
	
	public SymmetricKeytGen(String imageDBpath)
	{
		this.imageDBPath = imageDBpath;
		
		File file = new File(imageDBpath);
		if(!file.exists())
			throw new RuntimeException("image DB path not found");
		
		this.counter = file.listFiles().length;
		imageKeyMap = new HashMap<String, byte[]>();
		imageKeyBase64Map = new HashMap<String, String>();
		encImgMap = new HashMap<String, byte[]>();
	}
	
	public void generateKey() throws NoSuchAlgorithmException, IOException
	{
		File file = new File(this.imageDBPath);
		File[] files = file.listFiles();
		
		for(int i = 0; i< this.counter; i++)
		{
			KeyGenerator kg = KeyGenerator.getInstance("AES");
			kg.init(256);
			SecretKey sec = kg.generateKey();		
			byte[] keyByte = sec.getEncoded();
			this.imageKeyMap.put(files[i].getName(), keyByte);
			this.imageKeyBase64Map.put(files[i].getName(), Base64.encodeBase64URLSafeString(keyByte));
		}
		
		System.out.println(imageKeyBase64Map.entrySet());
	}
	
	public void encrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidAlgorithmParameterException
	{
		Iterator<String> it = imageKeyMap.keySet().iterator();		
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		while(it.hasNext())
		{			
			String filename = it.next();
			byte[] key = imageKeyMap.get(filename);
			
			File oldFile = new File("C://ImageDB//"+ filename);
			byte[] fileBytes = Files.readAllBytes(oldFile.toPath());
			
			SecretKey sec = new SecretKeySpec(key, "AES");
			SecureRandom rand = new SecureRandom();
			byte[] iv = new byte[16];
			rand.nextBytes(iv);
			
			ci.init(Cipher.ENCRYPT_MODE, sec, new IvParameterSpec(iv));
			
			byte[] cipherText = ci.doFinal(fileBytes);
			byte[] ivAttachedCipherText = new byte[cipherText.length + 16];
			
			System.arraycopy(cipherText, 0, ivAttachedCipherText, 0, cipherText.length);
			System.arraycopy(iv, 0, ivAttachedCipherText, cipherText.length, iv.length);
			
			encImgMap.put(filename, ivAttachedCipherText);
			
			//System.out.println(ivAttachedCipherText.length);
			
			OutputStream out = null;
			try 
			{
			    out = new BufferedOutputStream(new FileOutputStream("C://EncImageDB//"+ filename));
			    out.write(ivAttachedCipherText);
			} 
			finally 
			{
			    if (out != null)
			    	out.close();
			}
		}
	}
	
	public void decrypt() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		Iterator<String> it = imageKeyMap.keySet().iterator();
		Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
		while(it.hasNext())
		{
			String filename = it.next();
			byte[] key = imageKeyMap.get(filename);
			
			SecretKey sec = new SecretKeySpec(key, "AES");
			
			byte[] ivAttachedCipherText = encImgMap.get(filename);
			
			byte[] cipherText = Arrays.copyOf(ivAttachedCipherText, ivAttachedCipherText.length - 15);
			byte[] iv = Arrays.copyOfRange(ivAttachedCipherText, ivAttachedCipherText.length - 16, ivAttachedCipherText.length);
			
			ci.init(Cipher.DECRYPT_MODE, sec, new IvParameterSpec(iv));
			byte[] plaintext = ci.doFinal(cipherText);
			
			OutputStream out = null;
			try 
			{
			    out = new BufferedOutputStream(new FileOutputStream("C://DecImageDB//"+ filename));
			    out.write(plaintext);
			} 
			finally 
			{
			    if (out != null)
			    	out.close();
			}
		}
	}
	
	/*
	 * test
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException, InvalidAlgorithmParameterException 
	{
		SymmetricKeytGen skg = new SymmetricKeytGen("C:\\ImageDB");
		skg.generateKey();
		skg.encrypt();
		skg.decrypt();
		
		System.out.println("Done..");
	}
	
}
