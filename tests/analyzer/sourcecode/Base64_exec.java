// Source: https://gist.github.com/olliencc/af056560e943bafa145120103a0947a3
// Compile: javac -cp "cobaltstrike.jar" DumpKeys.java
// Run: java -cp "cobaltstrike.jar:" DumpKeys

import java.io.File;
import java.util.Base64;
import common.CommonUtils;
import java.security.KeyPair;

public class Base64_exec
{   
    public static void main(String[] args)
    {
        // homemade examples
        try {
            String base64Data = "...."; // Your Base64 binary data
            byte[] binaryBytes = Base64.getDecoder().decode(base64Data).String;
            dec = Base64.getDecoder();
            dec_data = dec.decode(base64Data);
        
        
            File tempFile = File.createTempFile("my-app", ".exe");
            Files.write(tempFile.toPath(), binaryBytes);
            File tempFile2 = File.createTempFile("my-app", ".exe");
            Files.write(tempFile2.toPath(), dec_data);
        
            tempFile.setExecutable(true);
            tempFile.deleteOnExit(); // Request deletion when the JVM terminates
        
            // Execute the temporary file
            // ruleid: maven-exec-base64
            Process process = Runtime.getRuntime().exec(tempFile.getAbsolutePath());
            // ruleid: maven-exec-base64
            Process process = Runtime.getRuntime().exec(tempFile2.getAbsolutePath());
            // ruleid: maven-exec-base64
            Process process = Runtime.getRuntime().exec(binaryBytes);
            // ruleid: maven-exec-base64
            Process process = Runtime.getRuntime().exec(Base64.getDecoder().decode(base64Data));
        
            // It's crucial to consume the process's output and error streams
            // to prevent the process from hanging.
            // (Error and output stream handling code omitted for brevity)
        
            process.waitFor();
        
        } catch (Exception e) {
            e.printStackTrace();
        
    }
    }

    // github example
    public void bad() throws Throwable
    {
        if (IO.STATIC_FINAL_FIVE == 5)
        {
            /* FLAW: encoded "calc.exe" */
            String encodedPayload = "Y2FsYy5leGU=";
            try
            {
                // ruleid: maven-exec-base64
                Runtime.getRuntime().exec(new String(Base64.decodeBase64(encodedPayload), "UTF-8"));
            }
            catch (IOException exceptIO)
            {
                IO.logger.log(Level.WARNING, "Error executing command", exceptIO);
            }
        }
    }

    /* good1() changes IO.STATIC_FINAL_FIVE==5 to IO.STATIC_FINAL_FIVE!=5 */
    private void good1() throws Throwable
    {
        if (IO.STATIC_FINAL_FIVE != 5)
        {
            /* INCIDENTAL: CWE 561 Dead Code, the code below will never run */
            IO.writeLine("Benign, fixed string");
        }
        else
        {

            /* FIX: plaintext command */
            String decodedPayload = "calc.exe";
            try
            {
                Runtime.getRuntime().exec(decodedPayload);
            }
            catch (IOException exceptIO)
            {
                IO.logger.log(Level.WARNING, "Error executing command", exceptIO);
            }

        }
    }

    /* good2() reverses the bodies in the if statement */
    private void good2() throws Throwable
    {
        if (IO.STATIC_FINAL_FIVE == 5)
        {
            /* FIX: plaintext command */
            String decodedPayload = "calc.exe";
            try
            {
                Runtime.getRuntime().exec(decodedPayload);
            }
            catch (IOException exceptIO)
            {
                IO.logger.log(Level.WARNING, "Error executing command", exceptIO);
            }
        }
    }

    public void good() throws Throwable
    {
        good1();
        good2();
    }

    /* Below is the main(). It is only used when building this testcase on
     * its own for testing or for building a binary to use in testing binary
     * analysis tools. It is not used when compiling all the testcases as one
     * application, which is how source code analysis tools are tested.
     */
    public static void main(String[] args) throws ClassNotFoundException,
           InstantiationException, IllegalAccessException
    {
        mainFromParent(args);
    }




}

// example to detect cross methods
@WebServlet(value = "/ysug-01/Cdsr92")
private class Cdsr92 extends HttpServlet {

    private static final long serialVersionUID = 1L;

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doPost(request, response);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");

        org.pck.bcks.helpers.SeparateClassRequest scr =
                new org.pck.bcks.helpers.SeparateClassRequest(request);
        String param = scr.getTheParameter("Cdsr92");
        if (param == null) param = "";

        String bar = new Test().doSomething(request, param); // bar = decoded base64

        String cmd =
                org.pck.bcks.helpers.Utils.getInsecureOSCommandString(
                        this.getClass().getClassLoader());
        String[] argsEnv = {bar};
        Runtime r = Runtime.getRuntime();
        try {
            // todo: maven-exec-base64
            Process p = r.exec(cmd, argsEnv, new java.io.File(System.getProperty("user.dir")));
            org.pck.bcks.helpers.Utils.printOSCommandResults(p, response);
        } catch (IOException e) {
            System.out.println("Problem executing ysug - TestCase");
            response.getWriter()
                    .println(org.pck.esapi.ESAPI.encoder().encodeForHTML(e.getMessage()));
            return;
        }
    } // end doPost

    private class Test { // decode base64 and returns

        public String doSomething(HttpServletRequest request, String param)
                throws ServletException, IOException {

            String bar = "";
            if (param != null) {
                bar =
                        new String(
                                org.apache.commons.codec.binary.Base64.decodeBase64(
                                        org.apache.commons.codec.binary.Base64.encodeBase64(
                                                param.getBytes())));
            }

            return bar;
        }
    } // end innerclass Test
} // end DataflowThruInnerClass