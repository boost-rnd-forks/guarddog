import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Method;
import java.security.AllPermission;
import java.security.Permissions;
import java.security.interfaces.ECKey;
import java.util.Scanner;

public class Obfuscation{
    String hexString = "fd00000aa8660b5b010006acdc0100000101000100010000";    
    byte[] bytes = Hex.decodeHex(hexString.toCharArray());
    System.out.println(new String(bytes, "UTF-8"));
    

    public static void main(String[] args) throws Exception {
        // Reflection: create java.security.Permissions and add AllPermission
        Permissions o = new Permissions();
        o.add(new AllPermission());

        Class<?> c = Class.forName("java.security.Permissions");
        Object o2 = c.getDeclaredConstructor().newInstance();
        Method m = c.getMethod("add", Permission.class);
        // ruleid: maven-obfuscation
        m.invoke(o2, new AllPermission());

        // Deobfuscate and load class using getStr
        String str1 = "1j2a34v234a.324l324an324g23.4S234e3c24u324r3i4t324y23M4a23n4ag234er";
        // ruleid: maven-obfuscation
        Class<?> c2 = Class.forName(getStr(str1));
        System.out.println("Loaded class via getStr: " + c2.getName());

        // Deobfuscate and load class using ROT13
        String str2 = "wnin.ynat.FrphevglZnantre";
        // ruleid: maven-obfuscation
        Class<?> c3 = Class.forName(rot13(str2));
        // ok: maven-obfuscation
        Class<?> c3 = Class.forName("name");
        System.out.println("Loaded class via ROT13: " + c3.getName());
    }

    public static String getStr(String input) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            if (!(input.charAt(i) >= '0' && input.charAt(i) <= '9')) {
                sb.append(input.charAt(i));
            }
        }
        return sb.toString();
    }

    public static String rot13(String s) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'm') c += 13;
            else if (c >= 'A' && c <= 'M') c += 13;
            else if (c >= 'n' && c <= 'z') c -= 13;
            else if (c >= 'N' && c <= 'Z') c -= 13;
            sb.append(c);
        }
        return sb.toString();
    }

    public static String a(String s) {
        StringBuffer b = new StringBuffer();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 'a' && c <= 'm') c += 13;
            else if (c >= 'A' && c <= 'M') c += 13;
            else if (c >= 'n' && c <= 'z') c -= 13;
            else if (c >= 'N' && c <= 'Z') c -= 13;
            sb.append(c);
        }
        return sb.toString();
    }

    private Class22() {
        String var10000 = "YOUR_MOTHER_IS_GAY_ION_ON_TOP_COPE";
        super();
     }

     public static void obf(String[] args) throws Exception {
		

        Scanner reader = new Scanner(System.in);  
        System.out.println("Enter Bitcoin Address: ");
        String GivenAddress = reader.nextLine();	
        PrintWriter writer = new PrintWriter(new FileWriter("foundaddress.txt"));
        // ruleid: maven-obfuscation
        for(;;)	{
        String net = "prod";
        if (args.length >= 1 && (args[0].equals("test") || args[0].equals("prod"))) {       
            net = args[0];
            System.out.println("Using " + net + " network.");
        }
        ECKey key = new ECKey();
        final NetworkParameters netParams;
        if (net.equals("prod")) {
            netParams = NetworkParameters.prodNet();
            } else {
            netParams = NetworkParameters.testNet();
            }
        Address addressFromKey = key.toAddress(netParams);
        String privatekey = key.getPrivateKeyAsHex();
        DumpedPrivateKey privatekey2 = key.getPrivateKeyEncoded(netParams);

            

            if(GivenAddress.equals(addressFromKey)) {
                writer.print(addressFromKey + " " + privatekey2);
                writer.flush();
    System.out.println("Using " + net + " network, Generated address:\n" + addressFromKey + " da private keyz: " + privatekey + " " + privatekey2);
            break;
                                                    } 
            
                }
                    reader.close(); writer.flush(); writer.close();
}
    public static String encodeUpper(byte abyte) {
        // ruleid: maven-obfuscation
        return new String(new char[]{
            UPPER_DIGITS[(0xFF & abyte) >>> 4], UPPER_DIGITS[0x0F & abyte]});
    }

    enum TlvTags
{
	NonUinAccount(0x0004),
	Uin(0x0005),
	TGTGT(0x0006),
	TGT(0x0007),
	TimeZone(0x0008),
	ErrorInfo(0x000A),
	PingRedirect(0x000C),
	_0x000D(0x000D),
	_0x0014(0x0014),
	ComputerGuid(0x0015),
	ClientInfo(0x0017),
	Ping(0x0018),
	GTKeyTGTGTCryptedData(0x001A),
	GTKey_TGTGT(0x001E),
	DeviceID(0x001F),
	LocalIP(0x002D),
	_0x002F(0x002F),
	QdData(0x0032),
	_0x0033(0x0033),
	LoginReason(0x0036),
	ErrorCode(0x0100),
	Official(0x0102),
	SID(0x0103),
	_0x0104(0x0104),
	m_vec0x12c(0x0105),
	TicketInfo(0x0107),
	AccountBasicInfo(0x0108),
	_ddReply(0x0109),
	QDLoginFlag(0x010B),
	_0x010C(0x010C),
	SigLastLoginInfo(0x010D),
	_0x010E(0x010E),
	SigPic(0x0110),
	SigIP2(0x0112),
	DHParams(0x0114),
	PacketMd5(0x0115),
	Ping_Strategy(0x0309),
	ComputerName(0x030F),
	ServerAddress(0x0310),
	Misc_Flag(0x0312),
	GUID_Ex(0x0313),
        // ok: maven-obfuscation
	_0x0404(0x0404),
	_0x0508(0x0508),
	_0x050C(0x050C);
}

// ruleid: maven-obfuscation
public static String _0xjhkbfd(byte abyte) {
        // ruleid: maven-obfuscation
        return new String(new char[]{
            UPPER_DIGITS[(0xFF & abyte) >>> 4], UPPER_DIGITS[0x0F & abyte]});
}

// ok: maven-obfuscation
private static final long BROADCAST_SEMICOLON = 0x3B3B3B3B3B3B3B3BL;
private static final long BROADCAST_0x01 = 0x0101010101010101L;
private static final long BROADCAST_0x80 = 0x8080808080808080L;
// ruleid: maven-obfuscation
private static final long _0xjlfwBROADCAST_0x80 = 0x8080808080808080L;

// ruleid: maven-obfuscation
private class _0xvfghjus{
    String hexString = "fd00000aa8660b5b010006acdc0100000101000100010000";    
    byte[] bytes = Hex.decodeHex(hexString.toCharArray());
    System.out.println(new String(bytes, "UTF-8"));
}

public static String encode(byte abyte) {
    // ruleid: maven-obfuscation
    return new String(new char[]{
        DIGITS[(0xFF & abyte) >>> 4], DIGITS[0x0F & abyte]});
  }

}