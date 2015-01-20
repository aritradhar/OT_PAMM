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

import com.util.Utils;


class FBTnode
{
	FBTnode[] children;
	boolean isLeaf;
	
	public FBTnode()
	{
		this.children = new FBTnode[2];
		this.children[0] = null;
		this.children[1] = null;
		
		this.isLeaf = false;
	}
}
public class FullyBinaryTree 
{
	int depth;
	FBTnode root;
	
	public FullyBinaryTree(int depth)
	{
		this.depth = depth;
		root = new FBTnode();
		Integer counter = 0, total = (int) Math.pow(2, depth);
		
		while(true)
		{
			if(counter >= total)
				break;
			
			this.addUpdate(Utils.bitString(depth ,counter));
			counter++;
		}
	}
	
	public void addUpdate(String num)
	{
		if(num.length() > depth)
			throw new IllegalArgumentException("Bad " + num + " value");
		
		FBTnode tempRoot = this.root;
		
		for(int i = 0; i< num.length(); i++)
		{
			int charNum = (int) num.charAt(i);
			
			if(charNum == 48)
			{
				if(tempRoot.children[0] != null)
					tempRoot = tempRoot.children[0];
				else
				{
					tempRoot.children[0] = new FBTnode();
					tempRoot = tempRoot.children[0];
				}
			}
			
			if(charNum == 49)
			{
				if(tempRoot.children[1] != null)
					tempRoot = tempRoot.children[1];
				else
				{
					tempRoot.children[1] = new FBTnode();
					tempRoot = tempRoot.children[1];
				}
			}
			
			if( i == num.length() - 1)
				tempRoot.isLeaf = true;
		}
		
		//this.root = tempRoot;
	}
	
	public void traverse(String s)
	{
		if(s.length() != this.depth)
			throw new IllegalArgumentException("Improper length " + s + " given");
			
		FBTnode tempRoot = this.root;
		
		for(int i = 0; i < s.length(); i++)
		{
			int c = (int) s.charAt(i);
			if(tempRoot.children[0] == null && tempRoot.children[1] == null)
				break;
			
			tempRoot = (c == 48) ? tempRoot.children[0] : tempRoot.children[1];
			
			System.out.print((c - 48));
		}
		
		System.out.println();
	}
	
	public static void main(String[] args) 
	{
		long start = System.currentTimeMillis();
		
		FullyBinaryTree FBT = new FullyBinaryTree(10);
		FBT.traverse("1011001001");
		
		long end = System.currentTimeMillis();
		
		System.out.println("Total time : " + (end - start) + " ms.");
	}
	
}
