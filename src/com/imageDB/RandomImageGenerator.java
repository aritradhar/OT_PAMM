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

package com.imageDB;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Random;

import javax.imageio.ImageIO;

public class RandomImageGenerator 
{
	int h;
	int w;
	int count;
	int textCount;
	String[] text;
	int[] pos;

	public RandomImageGenerator(int h, int w, int count) throws IOException
	{
		this.h = h;
		this.w = w;
		this.count = count;
		this.makeImage();
	}
	
	public RandomImageGenerator(int h, int w, int textCount, String[] text, int[] pos) throws IOException
	{
		this.h = h;
		this.w = w;
		this.textCount = textCount;
		this.text = text;
		this.pos = pos;
		
		makeImgaeWithSpecs();
	}

	public void makeImage() throws IOException
	{
		for(int i = 0; i< this.count; i++)
		{
			if(i % 100 == 0)
				System.out.print(i + " ");
			
			BufferedImage img = new BufferedImage(this.w, this.h, BufferedImage.TYPE_INT_RGB);
			Random rand = new Random();
			
			for(int x = 0; x < this.w; x++)
			{
				int r = rand.nextInt(256);
				int g = rand.nextInt(256);
				int b = rand.nextInt(256);
				int col = (r << 16) | (g << 8) | b;
				
				for(int y = 0; y< this.h; y++)
				{
					img.setRGB(x, y, col);
				}
			}
			Graphics graphics = img.getGraphics();
			graphics.setColor(Color.BLACK);
	        graphics.setFont(new Font("Arial Black", Font.BOLD, 50));
	        graphics.drawString("TEXT", 40, 50);
	        graphics.dispose();
			File f = new File("C:\\ImageDB\\autogen_" + i + ".jpg");
			ImageIO.write(img, "JPEG", f);
		}
		
		System.out.println();
	}
	
	public void makeImgaeWithSpecs() throws IOException
	{
		BufferedImage img = new BufferedImage(this.w, this.h, BufferedImage.TYPE_INT_RGB);
		Random rand = new Random();
	
		for(int x = 0; x < this.w; x++)
		{
			int r = rand.nextInt(256);
			int g = rand.nextInt(256);
			int b = rand.nextInt(256);
			int col = (r << 16) | (g << 8) | b;
			
			for(int y = 0; y< this.h; y++)
			{
				img.setRGB(x, y, col);
			}
		}
		
		Graphics graphics = img.getGraphics();
		graphics.setColor(Color.BLACK);
        graphics.setFont(new Font("Consolas", Font.BOLD, 100));
        
        for(int i = 0; i< this.textCount; i++)
        {
        	graphics.drawString(this.text[i], pos[i+1], pos[2 * i]);
        }
        graphics.dispose();
		File f = new File("C:\\ImageDB\\autogen.jpg");
		ImageIO.write(img, "JPEG", f);
	}
	
	public static void main(String[] args) throws IOException 
	{
		String[] s = {"A", "B", "C", "D"};
		int[] pos = {100, 300, 100, 200, 100, 30, 100, 40};
		
		new RandomImageGenerator(512, 512, 1024);
		System.out.println("done..");
	}
}
