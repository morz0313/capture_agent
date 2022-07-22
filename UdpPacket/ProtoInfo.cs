using System;
using System.Runtime.InteropServices;

namespace UdpPacket
{
    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct MacHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] DstAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
        public byte[] SrcAddress;
        // 上一层协议类型,0x0800表示IPv4，0x86dd表示IPv6
        public ushort Type;      
    }

    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct IPv4Header
    {
        // 版本(前4位),报头长度(后4位)
        // 版本用来表明协议实现的版本号,IPv4为0x0100。
        // 报头长度(Internet Header Length,IHL)是头部占32比特的数字,该字段为5,即5*32=160比特=20字节。
        public byte VersionAndHeaderLen;    
        // 服务类型       
        // 占8比特,前3当前已忽略,8保留未用,4~7分别代表延迟、吞吐量、可靠性和花费。
        // 这4比特的服务类型中只能置其中一项为1,可全为0,全为0为一般服务。
        public byte TypeOfService;              
        // 总长度
        // 指明整个数据报的长度(单位字节),最大长度为65535字节。
        public ushort TotalLen;                 
        // 标识
        // 用来唯一地标识主机发送的每一份数据报,通常每发一份报文,值会加1。
        public ushort Identification;           
        // 标志位、段偏移量
        // 标志位占低3比特,标志一份数据是否要求分段。
        // Reserved bit,预留位,必须为0。
        // Don't fragment,DF=1禁止分片,DF=0允许分片。
        // More fragment,MF=1非最后一片,MF=0最后一片。
        // 段偏移量占高13比特,指明该段距离原始数据报开始的位置。
        // 偏移量以8字节为单位。
        public ushort FragmentOffset;           
        // 生存期
        // 用来设置数据报最多可以经过的路由器数,通常设置为32、64、128等,每经过一个路由器,其值减1,直到0时该数据报被丢弃。
        public byte TimeToLive;
        // 协议
        // 指明IP层所封装的上层协议类型,ICMP(1)、IGMP(2) 、TCP(6)、UDP(17)。
        public byte Protocol;
        // 头部检验和
        // 对头部中每个16比特进行二进制反码求和。
        // 和TCP、UDP不同,不对头部后面的数据进行校验。
        public short HeaderChecksum;
        // 源地址
        public uint SrcAddress;      
        // 目的地址         
        public uint DestAddress;                
    }

    // IPv6基本报头可以携带可选的IPv6扩展报头,拓展报头可以为0个,可以为多个,当前项目中需要用到的是分段拓展报头
    // 协议规定分段拓展报头类型值为44
    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct IPv6Header
    {
        // 版本(Version),占4位,表明协议实现的版本号,IPv6为0x0110。
        // 通信分类(Traffic Class),占8位,标识对应IPv6的通道流类别,类似于IPv4的服务类型字段
        // 流标签(Flow Lable),IPv6新增字段,占20位,标记报文的数据流类型
        public uint Service;//4bit版本字段+6bitDS字段+2bitECM+20bit流标签
        // 有效载荷长度
        // 标识IPv6数据报中有效载荷部分(包括所有拓展头部分)的总长度,即除了IPv6的基本报头以外的其他部分总长度。
        public ushort PayloadLen; 
        // 下一个头部
        // 标识当前报头的下一个头部类型。
        public byte NextHeader;
        // 跳数限制
        // 类似于IPv4的生存期。
        public byte HopLimit;
        // 源地址
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] SrcAddress;
        // 目的地址
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] DestAddress;
    }

    // IPv6分段拓展报头定义
    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct IPv6FragmentHeader
    {
        // 标识当前报头的下一个头部类型。
        public byte NextHeader;
        // 预留位
        public byte Reserved;
        // 标志位、段偏移量
        // 段偏移量占低13比特,指明该段距离原始数据报开始的位置。
        // 标志位占高3比特,标志一份数据是否要求分段。
        // Reserved bits,预留两位,必须为0。
        // More fragment,MF=1非最后一片,MF=0最后一片。
        // 和IPv4头字段相反。
        public ushort FragmentOffset;
        // 标识
        // 具体请看IPv4头字段中含义。
        public uint Identification;
    }

    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct UDPHeader
    {
        public ushort SrcPort;      
        public ushort DesPort;        
        public ushort Length;
        // 检验和
        // 用来对UDP伪头部+UDP头部+数据进行校验。
        // 注意:和TCP不同,此字段是可选项,而TCP字段是必选的。
        // 初始值为全0值,然后计算校验和。
        // 计算方法:
        // 1.按每16位求和得出一个32位数。
        // 2.如果这32位数高16位不为0,则高16位加低16位再得到一个32位数。
        // 3.重复第2部直到高16位0,将低16位取反,得到校验和。
        // 4.若需校验数据不是偶数字节,则要填入一个全零字节补齐。
        public ushort Checksum;   
    }

    // Ipv4 Udp伪头部定义
    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct IPv4UdpHeader
    {
        // 源地址
        public uint SrcAddress;
        // 目的地址         
        public uint DestAddress;
        // 预留位
        public byte Reserved;        
        public byte Protocol;
        public ushort Length;
    }

    // IPv6 Udp伪头部定义
    [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    struct IPv6UdpHeader
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] SrcAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] DestAddress;
        public uint PayloadLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
        public byte[] Reserved;
        public byte NextHeader;
    }
}
