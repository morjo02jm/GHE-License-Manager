package com.ca;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.util.logging.Level;
import java.util.logging.Logger; 
 
public class RunCommand {
    private static final Logger LOGGER = Logger.getLogger(RunCommand.class.getName() );
	public static String execute(String cmd) {
		String output = null;
        try {
			String line;
			StringBuffer buffer = new StringBuffer();
            Runtime rt = Runtime.getRuntime();
            Process process = rt.exec(cmd);
	        InputStreamReader isr = new InputStreamReader( process.getInputStream() );
            BufferedReader br = new BufferedReader( isr );
 
            while( ( line = br.readLine() ) != null ) {
				buffer.append( line );
	   		}
            int exitValue = process.waitFor();
            System.out.println( "ExitValue: " + exitValue );
            output = buffer.toString();
        } catch (Exception e) {
			LOGGER.log(Level.SEVERE, e.toString(), e);
        }
        return output;
    }
}

