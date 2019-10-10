package core;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;

import core.Rules;

public class Firewall {
	
	// 2 Map to hold tcp(inbound, outbound) , udp(inbound, outbound)
    Map<String, Rules> tcp = new HashMap<String, Rules>();
    Map<String, Rules> udp = new HashMap<String, Rules>();
    
    //converting the ip to string format from long to find all the ips between the range and return as string
    public static String getIPFromLong(long iplong) {
	    return String.format("%d.%d.%d.%d",(iplong >>> 24) & 0xff,(iplong >>> 16) & 0xff,(iplong >>>  8) & 0xff,(iplong) & 0xff);
	}
	
	// converting the ip to long format from string 
	public static Long getLongFromIP(String ipAddress)
	{
		long result = 0;
		String[] ipAddressInArray = ipAddress.split("\\.");
		for (int i = 3; i >= 0; i--) {
			long ip = Long.parseLong(ipAddressInArray[3 - i]);
			result |= ip << (i * 8);
		}
		return result;
	}
	
	
	// constructor which loads the rule set .csv file
	public Firewall(String filepath){
       
        String csvFile =  filepath;
        BufferedReader br = null;
        String line = "";
        String csvSplit = ",";
        
        try {

            br = new BufferedReader(new FileReader(csvFile));
            while ((line = br.readLine()) != null) {
                String[] rule = line.split(csvSplit);
                String direction=rule[0].toLowerCase();
                String protocol=rule[1].toLowerCase();
                String portString=rule[2];
                String IP =rule[3];
                
                //check range of port
                int sPort , ePort;
                if(portString.contains("-"))
                {
                	String[] portArray = portString.split("-");
                	sPort = Integer.parseInt(portArray[0]);
                	ePort = Integer.parseInt(portArray[1]);
                }
                else
                {
                	sPort = Integer.parseInt(portString);
                	ePort = sPort;
                }
                
                //check range of ip
                
                String[] ipArray = null;
                if(IP.contains("-"))
                {
                	ipArray = IP.split("-");
                	
                }
                else
                {
                	ipArray = new String[2];
                	ipArray[0] = IP;
                	ipArray[1] = IP;
                }
                
               
                // based on protocol type save the information on respective HashMap
                if (protocol.equalsIgnoreCase("tcp"))
                {
                	Rules dir;
                	if(tcp.containsKey(direction)) dir= tcp.get(direction);
                	else dir = new Rules();
                	
                	for (long i = getLongFromIP(ipArray[0]); i <= getLongFromIP(ipArray[1]); i++) {
                		String[] val = getIPFromLong(i).split("\\.");
                		//System.out.println(Integer.parseInt(val[0])+"--"+Integer.parseInt(val[1])+"--"+Integer.parseInt(val[2])+"--"+Integer.parseInt(val[3]));
                        dir.addIpRules(Integer.parseInt(val[0]), Integer.parseInt(val[1]), Integer.parseInt(val[2]), Integer.parseInt(val[3]));
                    }
                	
                	while(sPort<=ePort) {
                		dir.addPort(sPort);
                 		sPort++;
                 	}
                 	
                	tcp.put(direction, dir);
               } 
                
                else if (protocol.equalsIgnoreCase("udp"))
               {
                	Rules dir;
                	if(udp.containsKey(direction)) dir= udp.get(direction);
                	else dir = new Rules();
               	
                	for (long i = getLongFromIP(ipArray[0]); i <= getLongFromIP(ipArray[1]); i++) {
                		String[] val = getIPFromLong(i).split("\\.");
                		//System.out.println(Integer.parseInt(val[0])+"--"+Integer.parseInt(val[1])+"--"+Integer.parseInt(val[2])+"--"+Integer.parseInt(val[3]));
                		dir.addIpRules(Integer.parseInt(val[0]), Integer.parseInt(val[1]), Integer.parseInt(val[2]), Integer.parseInt(val[3]));
                	}
               	
                	while(sPort<=ePort) {
                		dir.addPort(sPort);
                		sPort++;
                	}
                	
                	udp.put(direction, dir);
              }
                       
               
                else
                {
                	System.out.println("Unknown protocol");
                }
                	
            }
        }
            catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                if (br != null) {
                    try {
                        br.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
                
        
	}
    
	// To show all the rules in the HashMap - not part of assignment
    public void printRules(Map<String, Rules> ref1, String ref )
    {
    	if(ref.equalsIgnoreCase("tcp")) ref1 = tcp;
    	if(ref.equalsIgnoreCase("udp")) ref1 = udp;
    	for (Entry<String, Rules> entry : ref1.entrySet()) {
    		String typ = entry.getKey();
    		Rules obj = entry.getValue();
    		int[] hos = null;
    		int fourth = 0, third = 0, second = 0;
    		
    		Map<Integer, TreeMap<Integer, TreeMap<Integer, int[]>>>  tN = obj.networkFull;
    		for(Entry<Integer, TreeMap<Integer, TreeMap<Integer, int[]>>> en4 : tN.entrySet())
    		{
    			fourth = en4.getKey();
    			Map<Integer, TreeMap<Integer, int[]>> tI = en4.getValue();
    			for(Entry<Integer, TreeMap<Integer, int[]>> en3 : tI.entrySet())
    			{
    			    third = en3.getKey();
    				Map<Integer, int[]> tH =  en3.getValue();
    				for(Entry<Integer, int[]> en2 : tH.entrySet())
    				{
    					second = en2.getKey();
    					hos = en2.getValue();
    					for(int i=0 ; i <hos.length; i++)
    		    		{
    		    			if(hos[i]==1) System.out.println("Rule direction for tcp:" +typ+" Ip details -->"+fourth+"."+third+"."+second+"."+i);
    		    		}
    				}
    			}
    		}
    		
    		obj.portSet.forEach(System.out::println);
    		
    		
    		
    		
    	}
    }
    
    // checks the rulebook for policy
    public boolean check_packet(String direction, String protocol, int port, String ip_address, Rules obj)
    {
       	String[] startRange = ip_address.split("\\.");
    	int fourth = Integer.parseInt(startRange[0]);
    	int third = Integer.parseInt(startRange[1]);
    	int second = Integer.parseInt(startRange[2]);
    	int first = Integer.parseInt(startRange[3]);
    	
    	return obj.portSet.contains(port) && obj.networkFull.containsKey(fourth) && obj.inter.containsKey(third) && obj.host.containsKey(second) && obj.host.get(second)[first]==1;
    	   	
    }
    
    // method decides whether to accept a packet or not
    public boolean accept_packet(String direction, String protocol, int port, String ip_address) {
    	
    	if(protocol.equalsIgnoreCase("tcp"))
    	{
    		if(tcp.containsKey(direction))
    		{
    			Rules obj = tcp.get(direction);
    			return check_packet(direction, protocol, port, ip_address, obj);
    		}else
    		{
    			return false;
    		}
    	}else if(protocol.equalsIgnoreCase("udp"))
    	{
    		if(udp.containsKey(direction))
    		{
    			Rules obj = udp.get(direction);
    			return check_packet(direction, protocol, port, ip_address, obj);
    		}else
    		{
    			return false;
    		}
    		
    	}
    	else
    	{
    		return false;
    	}  
    }

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		long startTimeLoad = System.nanoTime();
		Firewall a1 = new Firewall("C://Hary/Code/Eclipse-workspace/Illumio/src/Rulestore/test.csv");
		long endtTimeLoad = System.nanoTime();
		System.out.println("Time taken to load IPs in milliseconds ->"+(endtTimeLoad - startTimeLoad)/1000000);
		
		/*Map<String, Rules> ref = null;
		a1.printRules(ref , "tcp"); */
		System.out.println("**************");
		
		long startTime = System.nanoTime();
		System.out.println(a1.accept_packet("inbound", "tcp", 75, "192.154.76.89"));
		System.out.println(a1.accept_packet("inbound", "tcp", 53, "192.167.2.2"));
		System.out.println(a1.accept_packet("inbound", "tcp", 65535, "192.167.2.6"));
		long endtTime = System.nanoTime();
		System.out.println("Time taken to lookup rules in milliseconds -->"+(endtTime - startTime)/1000000);
		
		
		
	}

}
