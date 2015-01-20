package com.userProfile;

public class UserProfileDataType 
{
	private boolean profileBit[];
	
	public UserProfileDataType(String bitString)
	{
		int profileSize = bitString.length();
		this.profileBit = new boolean[profileSize];
		for(int i = 0; i < profileSize; i++)
		{
			char c = bitString.charAt(i);
			if(c != '0' || c != '1')
				throw new NumberFormatException();
			
			profileBit[i] = (c == '1') ? true : false;
		}
	}
	
	public byte getUserInfo(int i)
	{
		return (byte) ((profileBit[i]) ? 0 : 1);
	}
}
