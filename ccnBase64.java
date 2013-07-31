
package org.ccnx.ccn.utils;

import org.apache.commons.codec.binary.Base64;

public class ccnBase64 extends Base64{

	private Base64 bas;


       /**
	*ccnBase64()
	*
	*Constructor
	*/
	
	public ccnBase64(){

		bas=new Base64();
	}

       /**
        *String encodeToString(byte[] data)
        *
        *This function replaced the Base64 class function
	*
	*@param data		data for encode 
	*
	*@return String 	encoded data
        */
	
	public String encodeToString(byte[] data){

		String toAnalize = bas.encodeToString(data);
		return this.base64FilterEncode(toAnalize.toCharArray());
	
	}

       /**
        *byte [] decode (String data)
        *
        *This function replaced the Base64 class function
        *
        *@param data            data for decode 
        *
        *@return byte[]         decoded data
        */

	public byte [] decode (String data){

		String toAnalize=this.base64FilterDecode(data.toCharArray());;
		return bas.decode(toAnalize);

	}
		
       /**
        *String base64FilterDecode(char [] name)
        *
        *This function look for especial characters and modifies those for understand the text
        *
        *@param name            data for modify 
        *
        *@return String         modified data
        */
	private String base64FilterDecode(char [] name){

                String test = "";

	        for(int i=1;i<name.length;i++){
	
        		if(name[i]=='%' && name[i+1]=='2' && name[i+2]=='B'){
	
        	                test=test+'+';
                	        i=i+2;
	
        	        }else if(name[i]=='%' && name[i+1]=='3' && name[i+2]=='D'){
	
        	                test=test+'=';
                		i=i+2;

			}else if(name[i]=='-' && name[i+1]=='-'){

				test=test+"//";
				i=i+1;
                       	}else{
        	        	test=test+name[i];
	
        	        }
           	}

                return test;

        }

       /**
        *String base64FilterEncode(char [] name)
        *
        *This function look for "//" and modifies it, because in ccn transmisions "//" transforms in "/"
        *
        *@param name            data for modify 
        *
        *@return String         modified data
        */

	private String base64FilterEncode(char [] name){

		String test = "";

		for(int i=0;i<name.length;i++){

                	if(name[i]=='/' && name[i+1]=='/'){

                        	test=test+"--";
                                i=i+1;

                        }else{

                                test=test+name[i];
                        }

                }

		return test;
	}
}
