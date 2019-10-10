package core;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class Rules {
	
	Map<Integer, TreeMap<Integer, TreeMap<Integer, int[]>>>  networkFull = new TreeMap<Integer,TreeMap<Integer, TreeMap<Integer, int[]>>>();
	Map<Integer, TreeMap<Integer, int[]>>  inter;
	Map<Integer, int[]>  host;
	Set<Integer> portSet = new HashSet<Integer>();
	
	public void addPort(int port)
	{
		if(!portSet.contains(port)) portSet.add(port);
	}
	
	public int[] arrInit()
	{
		int [] arrList = new int[256];
		Arrays.fill(arrList, 0);
		return arrList;
	}
	
	public void addIpRules(int fourth , int third , int second , int first)
	{
		if(networkFull.containsKey(fourth))
		{
			inter = networkFull.get(fourth);
			if(inter.containsKey(third))
			{
				host = inter.get(third);
				if(host.containsKey(second))
				{
					host.get(second)[first]=1;
				}
				else
				{
					int [] arrList = arrInit();
					host.put(second, arrList);
					host.get(second)[first]=1;
				}
			}
			else
			{
				int [] arrList = arrInit();
				host = new TreeMap<Integer, int[]>();
				host.put(second, arrList);
				host.get(second)[first]=1;
			}
			inter.put(third, (TreeMap<Integer, int[]>) host);
		}
		else
		{
			int [] arrList = arrInit();
			host = new TreeMap<Integer, int[]>();
			host.put(second, arrList);
			host.get(second)[first]=1;
			inter = new TreeMap<Integer, TreeMap<Integer, int[]>>();
			inter.put(third, (TreeMap<Integer, int[]>) host);
		}
		networkFull.put(fourth, (TreeMap<Integer, TreeMap<Integer, int[]>>) inter);
	}
	
}
