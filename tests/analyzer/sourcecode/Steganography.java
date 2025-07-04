import java.io.ByteArrayOutputStream;
import io.github.galliumdata.adumbra.*;


public class Steganography {
    // from documnetation example
    // Get the value of the bitmap column as a byte stream
    let inStream = context.packet.getJavaStream("bitmap");
    if (inStream === null) {
        return;
    }

    // The hidden message
    const now = new Date();
    const message = "Retrieved by " + context.connectionContext.userName + 
        " on " + now.getFullYear() + "/" + (now.getMonth()+1) + "/" + now.getDate();
    const messageBytes = context.utils.getUTF8BytesForString(message);
    const keyBytes = context.utils.getUTF8BytesForString("This is my secret key");

    // Hide the message in the bitmap
    const Encoder = Java.type("com.galliumdata.adumbra.Encoder");
    const ByteArrayOutputStream = Java.type("java.io.ByteArrayOutputStream");
    let outStream = new ByteArrayOutputStream();
    let encoder = new Encoder(1);
    // ruleid: maven-steganography
    encoder.encode(inStream, outStream, "png", messageBytes, keyBytes);
    context.packet.bitmap = outStream.toByteArray();



    // github example
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            throw new RuntimeException("First argument must be \"encode\" or \"decode\"");
        }

        String arg0 = args[0].toLowerCase().trim();
        if ("encode".equals(arg0)) {
            if (args.length < 5) {
                throw new RuntimeException("Parameters for encode must be: encode <input-file> <output-file> " +
                        "<message> <key> [<format> [<sec-level>]]");
            }

            String format = null;
            if (args.length >= 6) {
                format = args[5];
            }

            int secLevel = 0;
            if (args.length >= 7) {
                try {
                    secLevel = Integer.parseInt(args[6]);
                }
                catch(Exception ex) {
                    throw new RuntimeException("Invalid value for parameter");
                }
            }
            FileOutputStream fos = new FileOutputStream(args[2]);
            String message = args[3];
            String key = args[4];
            Encoder encoder = new Encoder(secLevel);
            FileInputStream inStr = new FileInputStream(args[1]);
            // ruleid: maven-steganography
            encoder.encode(inStr, fos,  format, message.getBytes(StandardCharsets.UTF_8), key.getBytes(StandardCharsets.UTF_8));
            fos.close();
        }

        // another github example
        @Test
        public void test() throws Exception {
    
            ImageIO.setUseCache(false);
    
            loadTestCases();
            for (TestCase tc: testCases) {
                System.out.println("Testing: " + tc.inFile + " -> " + tc.outFile + " secLevel: " + tc.secLevel);
                for (int i = 0; i < tc.numReps; i++) {
                    long startTime = System.currentTimeMillis();
                    Encoder encoder = new Encoder(tc.secLevel);
                    FileInputStream inStr = new FileInputStream(tc.inFile);
                    FileOutputStream fos = new FileOutputStream(tc.outFile);
                    // ruleid:  maven-steganography
                    encoder.encode(inStr, fos, tc.format, tc.message, tc.key);
                    fos.close();
                    System.out.println("Time for encoding: " + (System.currentTimeMillis() - startTime));
    
                    startTime = System.currentTimeMillis();
                    Decoder decoder = new Decoder();
                    FileInputStream inStr2 = new FileInputStream(tc.outFile);
                    byte[] decoded = decoder.decode(inStr2, tc.key);
                    System.out.println("Time for decoding: " + (System.currentTimeMillis() - startTime));
                    assertArrayEquals(tc.message, decoded);
                }
            }
    
            System.out.println("Test complete");


        }


        // stack overflow example
        public static void steg(String[] args) throws Exception {
            try {
                BufferedImage coverImageText = ImageIO.read(new File("originalPic.png"));       
                String s = "Java is a popular programming language, created in 1995.";
                // ruleid: maven-steganography
                coverImageText = Steganography.embedText(coverImageText, s);                                // embed the secret information
                Steganography.extractText(ImageIO.read(new File("textEmbedded.png")), s.length()); // extract the secret information
            } catch(IOException e) {        
                System.out.print("Error: " + e);
            }   
        }

        // github example
        public void saveWallet(){
            try {
    
                //writes the data to the stegno file
                //finally, move the file to the output directory
                // ruleid: maven-steganography
                Steganography a = new Steganography(this.file, new File(this.directory.getAbsolutePath()+"\\Wallet_Image_"+this.file.getName()));
                a.setText(this.EncryptedAddresses);
                a.saveImage();
    
                //finall, create JSON file with all bitcoin addresses format { "0":"dgdgs", "1":"sdfsdf" }
                String json = this.file.getName().substring(0, this.file.getName().lastIndexOf('.')) + ".json";
                new OutputJSON(this.address.toString(), new File(this.directory.getAbsolutePath()+"\\Wallet_Image_"+json)).export();
    
    
                //Clear static setting, for new addresses.. if not, it will contain previous addresses
                this.address.delete(0, this.address.length());
                EncryptedAddresses = "";
    
            } catch (Exception e){
    
                System.out.print(e);
    
            }
    
        }
         

    
}
