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
 *public byte[] handleInterest(ContentName filter ,String maID);
 *
 *Receives the data name which need to send and returns it
 *
 *@param filter  data name
 *@param maID 	MAs id 
 *@return byte[] data in byte Array
 */
public byte[] handleInterest(ContentName filter, String maID);

/**
 *public boolean authorizeContent(ContentName filter ,String maID);
 *
 *Authorizes or not to express an interest for do push petition
 *
 *@param filter 	 data name
 *@param maID 	 MA id 
 *@return boolean true if it authorizes, otherwise false
 */
public boolean authorizeContent(ContentName filter, String maID);

/**
 *public void handleContent(ContentName filter,byte[] content ,String maID);
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
