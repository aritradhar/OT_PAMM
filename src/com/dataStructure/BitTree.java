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

package com.dataStructure;

import java.math.BigInteger;
import java.util.Random;

import com.crypto.ClientCryptEngine;

public class BitTree 
{
	BigInteger message;
	BigInteger privateKey_server, N_server, N_client;
	int sPrime;
	String bitString;
	TreeNode Root;
	int treeSize;
	
	public BitTree(BigInteger message)
	{
		this.message = message;
		this.bitString = this.message.toString(2);
		treeSize = 0;
		makeTree();
		
	}
	
	public void setSPrime()
	{
		int RSIZE = this.message.bitLength();
		int nServerBits =this.N_server.bitLength();
		int nClientBits = this.N_client.bitLength();
		int s = 0;
		
		while(true)
		{
			s++;
			if(RSIZE < s * nServerBits)
				break;
		}
		
		while(true)
		{
			this.sPrime++;
			if((s + 1) * nServerBits < this.sPrime * nClientBits)
				break;
		}
	}
	
	public void makeTree()
	{
		System.out.println(bitString);
		Root = new TreeNode();
		for(int i = 0; i < bitString.length(); i++)
		{
			this.treeSize++;
			Character c = bitString.charAt(i);
			Root.addChild(new Integer(c.toString()));
		}
	}
	
	public String traverseTreeToi(int i)
	{
		if(i > this.treeSize)
		{
			throw new IllegalArgumentException("The given index is greater than the size of the bitr tree");
		}
		
		TreeNode tempRoot = Root;
		StringBuffer ret = new StringBuffer("");

		int counter = 0;
		while(true)
		{
			counter++;
			
			if((tempRoot.children[0] == null && tempRoot.children[1] == null) || counter == i)
				break;
			
			else if(tempRoot.children[0].isAccepted && !tempRoot.children[1].isAccepted)
			{
				tempRoot = tempRoot.children[0];
			}
			
			else if(!tempRoot.children[0].isAccepted && tempRoot.children[1].isAccepted)
			{
				tempRoot = tempRoot.children[1];
			}
			ret = ret.append(tempRoot.content);
		}
		return ret.toString();
	}
	
	public void updateNonAcceptedLeaves()
	{
		TreeNode tempRoot = Root;
		/*
		 * Go to the lowest non-accepting leaf node
		 */
		while(true)
		{
			if(tempRoot.children[0] == null && tempRoot.children[1] == null)
				break;
			
			tempRoot = (tempRoot.children[0].isAccepted)? tempRoot.children[0] : tempRoot.children[1];
			
		}
		TreeNode lowestNonAcceptingLeafNode = (!tempRoot.parent.children[0].isAccepted) ? tempRoot.parent.children[0] : tempRoot.parent.children[1];
		
		//System.out.print(lowestNonAcceptingLeafNode.content);
		while(true)
		{
			if(lowestNonAcceptingLeafNode.parent == null)
				break;
			
			lowestNonAcceptingLeafNode = lowestNonAcceptingLeafNode.parent;
			
			TreeNode nonAcceptingLeafNode = (!lowestNonAcceptingLeafNode.children[0].isAccepted) ? lowestNonAcceptingLeafNode.children[0] : lowestNonAcceptingLeafNode.children[1];
			System.out.println(nonAcceptingLeafNode.content);
		}
	}
	
	public BigInteger getEncNotAcceptedNodes()
	{
		this.setSPrime();
		
		BigInteger ans = BigInteger.ONE;
		int dPrime = this.treeSize;
		
		BigInteger msg = BigInteger.ZERO;
		ClientCryptEngine CCE = new ClientCryptEngine(N_server);
		ans = CCE.Encrypt(sPrime, msg);
		
		while(dPrime != 0)
		{
			System.out.println(dPrime);
			System.out.println(ans);
			ans = CCE.Encrypt(sPrime, msg);
			sPrime++;
			dPrime--;
		}
		return ans;
	}
	
	
	@Override
	public String toString() 
	{
		TreeNode tempRoot = Root;
		StringBuffer ret = new StringBuffer("");
		
		while(true)
		{
			if(tempRoot.children[0] == null && tempRoot.children[1] == null)
				break;
			
			else if(tempRoot.children[0].isAccepted && !tempRoot.children[1].isAccepted)
			{
				tempRoot = tempRoot.children[0];
			}
			
			else if(!tempRoot.children[0].isAccepted && tempRoot.children[1].isAccepted)
			{
				tempRoot = tempRoot.children[1];
			}
			ret = ret.append(tempRoot.content);
		}
		//System.out.println(depth);
		return ret.toString();
	}
	
	public static void main(String[] args) 
	{
		long start = System.currentTimeMillis();
		BitTree bt = new BitTree(new BigInteger(10, new Random()));
		//System.out.println(bt.toString());
		//System.out.println(bt.traverseTreeToi(1));	
		ClientCryptEngine CCE_server = new ClientCryptEngine(1024, null);
		ClientCryptEngine CCE_client = new ClientCryptEngine(1024, null);
		BigInteger n_server = CCE_server.getPublic();
		BigInteger d_server = CCE_server.getPrivate();
		BigInteger n_client = CCE_client.getPublic();
		BigInteger d_client = CCE_client.getPrivate();
		
		bt.N_client = n_client;
		bt.N_server = n_server;
		
		System.out.println(bt.getEncNotAcceptedNodes());
		
		long end = System.currentTimeMillis();
		
		System.out.println("Total time : " + (end  - start) + " ms.");
	}
	
}
