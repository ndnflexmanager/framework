//==============================================================================
// Brief   : Management Entity Application
// Authors : Jaime Garcia <jgr@it.uc3m.es>
//           Iván Vidal Fernández <ividal@it.uc3m.es>
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
 *This is an example of a Management Entity application which we will use as server.
 */

public class ApplicationME implements MEInterface{

                public static ManagementEntity me;
                public static ApplicationME app;

        public ApplicationME(){


        }

        public byte[] handleInterest(ContentName filter, String maID){

                String str= new String("WLIT, eduroam, WiFi-UC3M");
                return str.getBytes();

        }

       /**
	*This method authorizes or not to express an interest for push petition.
	*/
        public boolean authorizeContent(ContentName filter, String maID){

                return true;

        }

       /**
	*This method handles push data received.
	*/
        public void handleContent(ContentName filter,byte[] content, String maID) throws Exception{

                String d = new String(content, "UTF-8");
                System.out.println("This is the ssid: "+d);
        }


        public static void main(String [ ] args) throws Exception {

                /*Build our application*/
                app=new ApplicationME();

                /*Build the Management Entity of our application*/
                me=new ManagementEntity ("/uc3m/it","/management/faces","/me2374", app);
        }
}

