import com.sun.jna.*;
import com.sun.jna.ptr.*;
// ruleid: maven-dll-hijacking
package cz.autoclient.dllinjection;


public class DLL_Hijacking {

    public interface Kernel32 extends Library {
        Kernel32 INSTANCE = Native.load("kernel32", Kernel32.class);

        Pointer OpenProcess(int dwDesiredAccess, boolean bInheritHandle, int dwProcessId);
        Pointer VirtualAllocEx(Pointer hProcess, Pointer lpAddress, int dwSize, int flAllocationType, int flProtect);
        boolean WriteProcessMemory(Pointer hProcess, Pointer lpBaseAddress, byte[] lpBuffer, int nSize, IntByReference lpNumberOfBytesWritten);
        Pointer GetProcAddress(Pointer hModule, String lpProcName);
        Pointer GetModuleHandle(String lpModuleName);
        Pointer CreateRemoteThread(Pointer hProcess, Pointer lpThreadAttributes, int dwStackSize,
                                   Pointer lpStartAddress, Pointer lpParameter, int dwCreationFlags, Pointer lpThreadId);
    }

    public static void main(String[] args) {
        String dllPath = "C:\\Path\\To\\Your.dll";
        int pid = 1234; // Insert process ID manually or make a function to search for the target

        int PROCESS_ALL_ACCESS = 0x1F0FFF;
        Pointer process = Kernel32.INSTANCE.OpenProcess(PROCESS_ALL_ACCESS, false, pid);

        Pointer mem = Kernel32.INSTANCE.VirtualAllocEx(process, null, dllPath.length(), 0x1000 | 0x2000, 0x40);
        IntByReference written = new IntByReference(0);
        // ruleid: maven-dll-hijacking
        Kernel32.INSTANCE.WriteProcessMemory(process, mem, dllPath.getBytes(), dllPath.length(), written);

        Pointer loadLib = Kernel32.INSTANCE.GetProcAddress(Kernel32.INSTANCE.GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        // ruleid: maven-dll-hijacking
        Kernel32.INSTANCE.CreateRemoteThread(process, null, 0, loadLib, mem, 0, null);
    }

    // another github example
     /**
     * This method does all the work.
     * It takes DLL and injects into specified process and executes it.
     */
    @Override
    public void run() {

        // Construct DLL path with string terminator at the end ('\0')
        final String DllPath = dllPath.toAbsolutePath().toString() + '\0';

        WinNT.HANDLE hProcess = null;

        // (1) Start new process or inject into the existing one?
        if (processId > -1) {
            hProcess = Kernel32.INSTANCE.OpenProcess(WinNT.PROCESS_ALL_ACCESS, false, processId);
        } else {
            WinBase.STARTUPINFO startupInfo = new WinBase.STARTUPINFO();
            WinBase.PROCESS_INFORMATION.ByReference processInformation = new WinBase.PROCESS_INFORMATION.ByReference();

            // run some-app.exe in a new process
            boolean status = Kernel32.INSTANCE.CreateProcess(
                    processPath.toAbsolutePath().toString(),
                    null,
                    null,
                    null,
                    false,
                    new WinDef.DWORD(WinBase.CREATE_DEFAULT_ERROR_MODE),
                    Pointer.NULL,
                    null,
                    startupInfo,
                    processInformation);

            if (!status || processInformation.dwProcessId.longValue() <= 0) {
                throw new RuntimeException("Couldn't create the process!");
            }

            hProcess = processInformation.hProcess;
        }

        // (2) Allocate memory for the DLL's path in the target process
        Pointer pDllPath = Kernel32.INSTANCE.VirtualAllocEx(hProcess, null,
                new BaseTSD.SIZE_T(DllPath.length()),
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // (3) Write the path to the address of the memory we just allocated in the target process
        // (Write from the source buffer to allocated pDllPath)
        ByteBuffer bufSrc = ByteBuffer.allocateDirect(DllPath.length());
        bufSrc.put(DllPath.getBytes());

        Pointer ptrSrc = Native.getDirectBufferPointer(bufSrc);

        IntByReference bytesWritten = new IntByReference(); // This may be 'null' if we aren't interested
        // ruleid: maven-dll-hijacking
        Kernel32.INSTANCE.WriteProcessMemory(hProcess, pDllPath, ptrSrc, DllPath.length(), bytesWritten);
        if (bytesWritten.getValue() != DllPath.length()) {
            throw new RuntimeException("Wrong amount of bytes written! Is: " + bytesWritten.getValue() + "! Should've been: " + DllPath.length());
        }

        // (4) Create a Remote Thread in the target process which
        // calls LoadLibraryA with our dllpath as an argument -> program loads our dll
        NativeLibrary kernel32Library = NativeLibrary.getInstance("kernel32");
        Function LoadLibraryAFunction = kernel32Library.getFunction("LoadLibraryA");

        DWORDByReference threadId = new DWORDByReference(); // This may also be 'null' if we aren't interested
        // ruleid: maven-dll-hijacking
        HANDLE hThread = Kernel32.INSTANCE.CreateRemoteThread(hProcess, null, 0,
                LoadLibraryAFunction, pDllPath, 0, threadId);

        // (5) Wait for the execution of our loader thread to finish
        int waitResult = Kernel32.INSTANCE.WaitForSingleObject(hThread, 20 * 1000); // Wait 20 seconds (or INFINITE?)
        if (WAIT_OBJECT_0 != waitResult) {
            throw new RuntimeException("Something went wrong during waiting for execution of our loader thread to finish!");
        }

        log.info("Dll path allocated at: {}", pDllPath);

        // (6) Free the memory allocated for our dll path
        // TODO should I delete this?
        if (!Kernel32.INSTANCE.VirtualFreeEx(hProcess, pDllPath, new SIZE_T(0), WinNT.MEM_RELEASE)) {
            throw new RuntimeException("Couldn't delete the memory we've allocated for pDllPath string value!");
        }

        // another github
        public static final String DLL_32 = "StopThat.dll";
   public static final String INJECTOR_32 = "RemoteDLLInjector32.exe";
   public static final String DLL_64 = "StopThat_64.dll";
   public static final String INJECTOR_64 = "RemoteDLLInjector64.exe";
   
   /** How should the command be sent to the target injector program.
    *  Known variables:
    *    $PID - process id of the target process
    *    $DLL_PATH - absolute path to the DLL file
    *    $PNAME - name of the process
    */
   private static String command_line_pattern = "$PID \"$DLL_PATH\"";
   private static String directory = "./stop_flashing";
   private static int version = 32;
   
   //Paths to dll file and the injection program
   private static File dll;
   private static File injector;
   /** Configure directory where dll and the dll injection application are located.
    * @param path 
    */
   public static void setDirectory(String path) {
     if(!path.equals(directory)) {
       directory = path;
       //Clear paths
       dll = null;
       injector = null;
     }
   }
   /**
    * Will convert the String paths to File objects. The paths to 
    * injector executable and injected DLL are kept as final to prevent easy abuse of this program.
    */
   private static void createPaths() {
     if(version==32) {
       dll = new File(directory+"/"+DLL_32);
       injector = new File(directory+"/"+INJECTOR_32);
     }
     else {
       dll = new File(directory+"/"+DLL_64);
       injector = new File(directory+"/"+INJECTOR_64);
     }
   }
   
   public static boolean available() {
     createPaths();
     return dll.exists() && injector.exists();
   }
   public static void inject() {
     if(available()) {
       new InjectionThread().start();
     }    
   }
   public static void inject(InjectionResult res) {
     if(available()) {
       new InjectionThread(res).start();
     }
     else
       res.run(false, "Injection files are missing.");
   }
   public static Process injectNow() throws ProcessNotFoundException, IOException {
     int pid = NativeProcess.getProcessId(cz.autoclient.PVP_net.ConstData.process_name);
     if(pid>0) {
       String command_line = DLLInjector.getCommandLine(pid);
       return Runtime.getRuntime().exec(command_line);
     }
     else 
       throw new ProcessNotFoundException("Process not seen in tasklist.", cz.autoclient.PVP_net.ConstData.process_name);
   }
   public static String getCommandLine(int pid) {
     return injector.getAbsolutePath()+
                             " "+
                             command_line_pattern.replace("$PID", ""+pid)
                                                 .replace("$PNAME", cz.autoclient.PVP_net.ConstData.process_name)
                                                 .replace("$DLL_PATH", dll.getAbsolutePath());
     
   }
    }



    // another github example 
    static Kernel32 kernel32 = (Kernel32) Native.loadLibrary("kernel32.dll", Kernel32.class, W32APIOptions.ASCII_OPTIONS);
    static PsapiExt psapi = (PsapiExt) Native.loadLibrary("psapi", PsapiExt.class, W32APIOptions.UNICODE_OPTIONS);
    
	public static void main(String[] args) {
		if(args.length < 2) {
			System.out.println("JLoadLibrary <Process-ID> <DLL-Path>");
			System.exit(0);
		}
		
		try {
           	boolean injectResult = inject(Integer.valueOf(args[0]), args[1]);

           	if(injectResult) 
           		System.out.println("Injection successful!");
           	else
           		System.out.println("Injection failed!");
        } catch (Exception e) {
            e.printStackTrace();
        }
	}
	
	public static boolean inject(int processID, String dllName) {
		DWORD_PTR processAccess = new DWORD_PTR(0x43A);
		
		HANDLE hProcess = kernel32.OpenProcess(processAccess, new BOOL(false), new DWORD_PTR(processID));
		if(hProcess == null) {
			System.out.println("Handle was NULL! Error: " + kernel32.GetLastError());
			return false;
		}
		
		DWORD_PTR loadLibraryAddress = kernel32.GetProcAddress(kernel32.GetModuleHandle("KERNEL32"), "LoadLibraryA");
		if(loadLibraryAddress.intValue() == 0) {
			System.out.println("Could not find LoadLibrary! Error: " + kernel32.GetLastError());
			return false;
		}
		
		LPVOID dllNameAddress = kernel32.VirtualAllocEx(hProcess, null, (dllName.length() + 1), new DWORD_PTR(0x3000), new DWORD_PTR(0x4));
		if(dllNameAddress == null) {
			System.out.println("dllNameAddress was NULL! Error: " + kernel32.GetLastError());
			return false;
		}

		Pointer m = new Memory(dllName.length() + 1);
		m.setString(0, dllName); 
        // ruleid: maven-dll-hijacking
		boolean wpmSuccess = kernel32.WriteProcessMemory(hProcess, dllNameAddress, m, dllName.length(), null).booleanValue();
		if(!wpmSuccess) {
			System.out.println("WriteProcessMemory failed! Error: " + kernel32.GetLastError());
			return false;
		}
		// ruleid: maven-dll-hijacking
		DWORD_PTR threadHandle = kernel32.CreateRemoteThread(hProcess, 0, 0, loadLibraryAddress, dllNameAddress, 0, 0);			
		if(threadHandle.intValue() == 0) {
			System.out.println("threadHandle was invalid! Error: " + kernel32.GetLastError());
			return false;
		}
		
		kernel32.CloseHandle(hProcess);
		
		return true;
	}
}