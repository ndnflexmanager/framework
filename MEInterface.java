//==============================================================================
// Brief   : Management Entity Interface
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
 *Interfaz for ManagementEntity application
 */

public interface MEInterface{

/**
 *public byte[] handleInterest(ContentName filter);
 *
 *Receives the data name which need to send and returns it
 *
 *@param filter  data name
 *@param maID 	MAs id 
 *@return byte[] data in byte Array
 */
public byte[] handleInterest(ContentName filter, String maID);

/**
 *public boolean authorizeContent(ContentName filter);
 *
 *Authorizes or not to express an interest for do push petition
 *
 *@param filter 	 data name
 *@param maID 	 MA id 
 *@return boolean true if it authorizes, otherwise false
 */
public boolean authorizeContent(ContentName filter, String maID);

/**
 *public void handleContent(ContentName filter,byte[] content);
 *
 *Handles the data after push petition
 *
 *@param filter 		data name
 *@param content		data content
 *@param maID 		MA id 		
 *@return boolean  	true if it authorizes, otherwise false
 */
public void handleContent(ContentName filter, byte[] content, String maID) throws Exception;

}
