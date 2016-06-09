package com.ca;
import java.io.InputStreamReader;
import java.io.BufferedReader;
 
public class RunCommand
{
    public static String execute(String cmd)
    {
		String output = null;
 
        try
        {
			String line;
			StringBuffer buffer = new StringBuffer();
 
            Runtime rt = Runtime.getRuntime();
            Process process = rt.exec(cmd);
 
	    InputStreamReader isr = new InputStreamReader( process.getInputStream() );
            BufferedReader br = new BufferedReader( isr );
 
            while( ( line = br.readLine() ) != null )
            {
			/*	buffer.append( "<br>" ); */
				buffer.append( line );
	   		}
 
            int exitValue = process.waitFor();
            System.out.println( "ExitValue: " + exitValue );
 
            output = buffer.toString();
        }catch (Throwable t){
        	t.printStackTrace();
        }
 
        return output;
    }

}
