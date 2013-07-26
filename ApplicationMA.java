package org.ccnx.ccn.utils;

import java.lang.*;
import java.io.*;
import java.util.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.ccnx.ccn.CCNHandle;
import org.ccnx.ccn.CCNInterestListener;
import org.ccnx.ccn.config.SystemConfiguration;
import org.ccnx.ccn.protocol.ContentName;

public class ApplicationMA implements MAInterface{

        public ManagementAgent ma;

       /**
        *public ApplicationMA()
        *
        *Constructor Initializes ManagementAgent
        *
        */

        public ApplicationMA(String agent)throws Exception{
		
		ma=new ManagementAgent ("/uc3m/it","/management/faces", agent, this);
        }

       /**
        *public byte[] handleInterest(ContentName filter);
        *
        *Receives the data name which need to send and returns it
        *
        *@param filter          data name
        *@return byte[]         data in byte Array
        */
        public byte[] handleInterest(ContentName filter){

                String str= new String("wlitMA, eduroamMA, wifi-UC3MMA");
                return str.getBytes();
        }

	/**
        *public boolean authorizeContent(ContentName filter);
        *
        *Authorizes or not to express an interest for do push petition
        *
        *@param filter          data name
        *@return boolean        true if it authorizes, otherwise false
        */
        public boolean authorizeContent(ContentName filter){

                return true;

        }

       /**
        *public void handleContent(ContentName filter,byte[] content);
        *
        *Handles the data after push petition
        *
        *@param filter         data name
        *@param content        data content
        *@return boolean       true if it authorizes, otherwise false
        */
        public void handleContent(ContentName filter,byte[] content) throws Exception{

		String d = new String(content, "UTF-8");
		System.out.println("This is the ssid: "+d);
        }

       /**
	*public void applicationLogic()
	*
	*This function sends pull and push messages to Me
	*
	*/

	public void applicationLogic() throws Exception{
			
			Thread.sleep(1000);

			
	 		ContentName argName_pull = ContentName.fromURI("/accesNetworks/GPS/wlan");
                        ContentName argName_push = ContentName.fromURI("/faces/wlan0/ssid");
                        /*Express pull interest*/
                        byte[] data=ma.pull(argName_pull);

                        String d = new String(data, "UTF-8");
                        System.out.println("This are the networks availables:"+d);

                        /*Express push interest*/
                        String str= new String("wlit");
                        byte []data_push= str.getBytes();
                        if(ma.push(argName_push,data_push)==false){

                                System.out.println("Error push MA");
                        }else{
                                System.out.println("Push MA ok");
                        }

	}

	
	/**
	*public static void main(String [ ] args)
	*
	*@param args		the MA name, it must start with slash("/") 
	*	
	*/
        public static void main(String [ ] args) throws Exception{

                        /*Build our application*/

                       ApplicationMA app=new ApplicationMA(args[0]);


     			app.applicationLogic();
		 
          }

}

