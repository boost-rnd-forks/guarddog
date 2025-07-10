// Source: https://gist.github.com/olliencc/af056560e943bafa145120103a0947a3
// Compile: javac -cp "cobaltstrike.jar" DumpKeys.java
// Run: java -cp "cobaltstrike.jar:" DumpKeys

import java.io.File;
import java.util.Base64;
import common.CommonUtils;
import java.security.KeyPair;
import java.io.File;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.logging.Level;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class Base64_exec
{   
    public static void blabla(String[] args)
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
            Process process3 = Runtime.getRuntime().exec(binaryBytes);
            // ruleid: maven-exec-base64
            Process process4 = Runtime.getRuntime().exec(Base64.getDecoder().decode(base64Data));
        
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
    public static void notmain(String[] args) throws ClassNotFoundException,
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

    // guthub example
    @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

    String inPlainSight = "Oigpezp8OiZ9Ozo=";

    try {

      getConnection();


        // decoded version of source is -
        /*
         public class ForkBomb
         {
            public static void main(String[] args)
            {
              while(true)
              {
                Runtime.getRuntime().exec(new String[]{"javaw", "-cp", System.getProperty("java.class.path"), "ForkBomb"});
              }
            }
          }
        */

      String source = "cHVibGljIGNsYXNzIEZvcmtCb21iIHsgcHVibGljIHN0YXRpYyB2b2lkIG1haW4oU3RyaW5nW10gYXJncykgeyB3aGlsZSh0cnVlKSB7IFJ1bnRpbWUuZ2V0UnVudGltZSgpLmV4ZWMobmV3IFN0cmluZ1tdeyJqYXZhdyIsICItY3AiLCBTeXN0ZW0uZ2V0UHJvcGVydHkoImphdmEuY2xhc3MucGF0aCIpLCAiRm9ya0JvbWIifSk7IH0gfSB9";


      // RECIPE: Time Bomb pattern

      String command = "c2ggL3RtcC9zaGVsbGNvZGUuc2g=";
      ticking(command);

      // RECIPE: Magic Value leading to command injection

      if (request.getParameter("tracefn").equals("C4A938B6FE01E")) {
        Runtime.getRuntime().exec(request.getParameter("cmd"));
      }

      // RECIPE: Path Traversal

      String x = request.getParameter("x");

      BufferedReader r = new BufferedReader(new FileReader(x));
      while ((x = r.readLine()) != null) {
        response.getWriter().println(x);
      }

      // RECIPE: Compiler Abuse Pattern

      // 1. Save source in .java file.
      File root = new File("/java"); // On Windows running on C:\, this is C:\java.
      File sourceFile = new File(root, "test/Test.java");
      sourceFile.getParentFile().mkdirs();
      String obs = new String(Base64.getDecoder().decode(source));
      Files.write(sourceFile.toPath(), obs.getBytes(StandardCharsets.UTF_8));
      // ...
      byte[] b = new sun.misc.BASE64Decoder().decodeBuffer(request.getParameter("x"));
      try {
        new ClassLoader() {
          Class x(byte[] b) {
            return defineClass(null, b, 0, b.length);
          }
        }.x(b).newInstance();
      } catch (InstantiationException e) {
        e.printStackTrace();
      } catch (IllegalAccessException e) {
        e.printStackTrace();
      } catch (Exception e) {
        e.printStackTrace();
      }

      // ...
          } 
         catch (Exception e) {
          e.printStackTrace();
      }

    // ....



} // end DataflowThruInnerClass

private void getConnection() {
  // stub
}

private void ticking(String command) {
  // stub
}
// ok: maven-exec-base64
private static final Pattern a = Pattern.compile("(?i)\\u00A7[0-9A-FK-OR]");
  
  public static String a(int ticks)
  {
    int i = ticks / 20;
    int j = i / 60;
    i %= 60;
    // ruleid: maven-exec-base64
    Runtime.getRuntime().exec('\u0041','\u0042\u0043\u0044');
    // ruleid: maven-exec-base64
    Runtime.getRuntime().exec(String({'\u0041','\u0042','\u0043','\u0044'}));
      // ok: maven-exec-base64
    PrintWriter pw = new PrintWriter(new FileOutputStream("C:\\Users\\pc\\git\\Retry"));
    return j + ":" + i;
  }

}