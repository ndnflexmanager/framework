//==============================================================================
// Brief   : Management Agent Application
// Authors : Jaime Garcia <jgr@it.uc3m.es>
//	     Iván Vidal Fernández <ividal@it.uc3m.es>
//           Daniel Corujo <dcorujo@av.it.pt>
//------------------------------------------------------------------------------
// Flexible Management Framework
//
// Copyright (C) 2013 Universidad Carlos III de Madrid
// Copyright (C) 2013 Universidade Aveiro
// Copyright (C) 2013 Instituto de Telecomunicações - Pólo Aveiro
//
// This software is distributed under a license. The full license
// agreement can be found in the file LICENSE in this distribution.
// This software may not be copied, modified, sold or distributed
// other than expressed in the named license agreement.
//
// This software is distributed without any warranty.
//==============================================================================

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
/**
 *This is an example of a Management Agent application which we will use for pull and push petitions.
 */
public class ApplicationMA implements MAInterface{

        public static ManagementAgent ma;
        public static ApplicationMA app;

        public ApplicationMA(){


        }

       /**
	*This method returns data with param name, we use it for pull messages.
	*(without effect in this case)
	*/
        public byte[] handleInterest(ContentName filter){

                return null;
        }

       /**
	*This method authorizes or not to express an interest for push petition
	*(without effect in this case)
	*/
        public boolean authorizeContent(ContentName filter){

                return true;

        }

       /**
	*This method handles push data received
	*(without effect in this case)
	*/
        public void handleContent(ContentName filter,byte[] content) throws Exception{

        }

	public static void main(String [ ] args) throws Exception{

                        /*Build our application*/
                        app=new ApplicationMA();

                        /*Build the Management Agent of our application*/
                        ma=new ManagementAgent ("/uc3m/it","/management/faces", "/agent1523","/me2374", app);

                        ContentName argName_pull = ContentName.fromURI("/accesNetworks/GPS/wlan");
                        ContentName argName_push = ContentName.fromURI("/faces/wlan0/ssid");
                        /*Express pull interest*/
                        byte[] data=ma.pull(argName_pull);
                        String d = new String(data, "UTF-8");
                        System.out.println("This are the networks availables:"+d);

                        /*Express push interest*/
                        String str= new String("WLIT");
                        byte []data_push= str.getBytes();

                        if(ma.push(argName_push,data_push)==false){

                                System.out.println("Error push MA");
                        }else{
                                System.out.println("Push MA ok");
                        }
	}

}

