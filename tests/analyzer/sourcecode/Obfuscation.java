


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


}