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

public class TreeNode
{
	/*
	 * Right now address is unused
	 */
	String address;
	int content;
	TreeNode[] children;
	/*
	 * Keep the parent information
	 * to traverse backwards
	 */
	TreeNode parent;
	boolean isAccepted;
	boolean isLeaf;
	
	/*
	 * Only for ROOT node
	 */
	public TreeNode()
	{
		children = new TreeNode[2];
		children[0] = null;
		children[1] = null;
		this.isAccepted = true;
		parent = null;
	}
	
	public TreeNode(int content)
	{
		children = new TreeNode[2];
		children[0] = null;
		children[1] = null;
		this.content = content;
		this.isAccepted = true;
	}
	
	public TreeNode(int content, boolean isAccepted)
	{
		children = new TreeNode[2];
		children[0] = null;
		children[1] = null;
		this.content = content;
		this.isAccepted = isAccepted;
		this.isLeaf = true;
	}
	
	public String getAddress()
	{
		return this.address;
	}
	
	public TreeNode getChild(int i)
	{
		return this.children[i];
	}
	
	public void addChild(int i)
	{
		TreeNode tempRoot = this;
		
		while(true)
		{
			if(tempRoot.children[0] == null && tempRoot.children[1] == null)
				break;
			
			else if(tempRoot.children[0].isAccepted && !tempRoot.children[1].isAccepted)
				tempRoot = tempRoot.children[0];
			
			else if(!tempRoot.children[0].isAccepted && tempRoot.children[1].isAccepted)
				tempRoot = tempRoot.children[1];
			
		}
		
		if(i == 0)
		{
			tempRoot.isLeaf = false;
			tempRoot.children[0] = new TreeNode(0,true);
			tempRoot.children[1] = new TreeNode(0, false);
			
			tempRoot.children[0].parent = tempRoot.children[1].parent = tempRoot;
		}
		
		else
		{
			tempRoot.isLeaf = false;
			tempRoot.children[0] = new TreeNode(0, false);
			tempRoot.children[1] = new TreeNode(1,true);
			
			tempRoot.children[0].parent = tempRoot.children[1].parent = tempRoot;
		}
	}
	
}
