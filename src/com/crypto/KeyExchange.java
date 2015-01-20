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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class KeyExchange implements Runnable {
	byte bob[], alice[];
	boolean doneAlice = false;
	byte[] ciphertext;

	BigInteger aliceP, aliceG;
	int aliceL;

	public synchronized void run() {
		if (!doneAlice) {
			doneAlice = true;
			doAlice();
		}
		else doBob();
	}

	public synchronized void doAlice() {
		try {
			// Step 1:  Alice generates a key pair
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
			kpg.initialize(1024);
			KeyPair kp = kpg.generateKeyPair();
			
			// Step 2:  Alice sends the public key and the
			// 		Diffie-Hellman key parameters to Bob
			Class dhClass = Class.forName(
								"javax.crypto.spec.DHParameterSpec");
			DHParameterSpec dhSpec = (
							(DHPublicKey) kp.getPublic()).getParams();
			aliceG = dhSpec.getG();
			aliceP = dhSpec.getP();
			aliceL = dhSpec.getL();
			alice = kp.getPublic().getEncoded();
			notify();

			// Step 4 part 1:  Alice performs the first phase of the
			//		protocol with her private key
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(kp.getPrivate());

			// Step 4 part 2:  Alice performs the second phase of the
			//		protocol with Bob's public key
			while (bob == null) {
				wait();
			}
			KeyFactory kf = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(bob);
			PublicKey pk = kf.generatePublic(x509Spec);
			ka.doPhase(pk, true);

			// Step 4 part 3:  Alice can generate the secret key
			byte secret[] = ka.generateSecret();

			// Step 6:  Alice generates a DES key
			
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(secret);
			byte[] sec1 = md.digest();
			
			byte []sec = Arrays.copyOf(sec1, 32); 
			SecretKey key = new SecretKeySpec(sec, "AES");
			
			// Step 7:  Alice encrypts data with the key and sends
			//		the encrypted data to Bob
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
			byte[] iv = new byte[16];
			Arrays.fill(iv, (byte)0);
			c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			ciphertext = c.doFinal(
						"Stand and unfold yourself".getBytes());
			notify();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public synchronized void doBob() {
		try {
			// Step 3:  Bob uses the parameters supplied by Alice
			//		to generate a key pair and sends the public key
			while (alice == null) {
				wait();
			}
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
			DHParameterSpec dhSpec = new DHParameterSpec(
								aliceP, aliceG, aliceL);
			kpg.initialize(dhSpec);
			KeyPair kp = kpg.generateKeyPair();
			bob = kp.getPublic().getEncoded();
			notify();

			// Step 5 part 1:  Bob uses his private key to perform the
			//		first phase of the protocol
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(kp.getPrivate());

			// Step 5 part 2:  Bob uses Alice's public key to perform
			//		the second phase of the protocol.
			
			KeyFactory kf = KeyFactory.getInstance("DH");
			X509EncodedKeySpec x509Spec =
							new X509EncodedKeySpec(alice);
			PublicKey pk = kf.generatePublic(x509Spec);
			ka.doPhase(pk, true);
			

			// Step 5 part 3:  Bob generates the secret key
			byte secret[] = ka.generateSecret();

			// Step 6:  Bob generates a DES key
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(secret);
			byte[] sec1 = md.digest();
			
			byte []sec = Arrays.copyOf(sec1, 32);  
			SecretKey key = new SecretKeySpec(sec, "AES");
			
			// Step 8:  Bob receives the encrypted text and decrypts it
			
			byte[] iv = new byte[16];
			Arrays.fill(iv, (byte)0);
			
			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
			c.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			while (ciphertext == null) {
				wait();
			}
			byte plaintext[] = c.doFinal(ciphertext);
			System.out.println("Bob got the string " +
						new String(plaintext));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void main(String args[]) {
		KeyExchange test = new KeyExchange();
		new Thread(test).start();		// Starts Alice
		new Thread(test).start();		// Starts Bob
	}
}