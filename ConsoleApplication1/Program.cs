using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UdpPacket;
using SharpPcap;
using SharpPcap.WinPcap;
using System.Net;

namespace ConsoleApplication1
{
    class Program
    {
        static WinPcapDevice GetNetDev(string ip)
        {
            var devices = CaptureDeviceList.Instance;
            devices.Refresh();

            if (1 > devices.Count)
            {
                Console.WriteLine("no network device on this pc!");
                return null;
            }
            foreach (var dev in devices)
            {
                WinPcapDevice dev_interface = (WinPcapDevice)dev;
                foreach (var addr in dev_interface.Addresses)
                {
                    if (ip == addr.Addr.ToString())
                    {
                        return dev_interface;
                    }
                }
            }

            Console.WriteLine("no ip:{0} network device on this pc!", ip);
            return null;
        }

        static void Main(string[] args)
        {
            WinPcapDevice netdev = GetNetDev("172.21.33.48");
            if (null == netdev)
            {
                return;
            }

            ushort srcport = 162;
            byte[] srcip = IPAddress.Parse("172.21.33.100").GetAddressBytes();
            byte[] srcmac = netdev.Interface.MacAddress.GetAddressBytes();

            ushort dstport = 30000;
            byte[] dstip = IPAddress.Parse("172.21.33.48").GetAddressBytes();
            byte[] dstmac = netdev.Interface.MacAddress.GetAddressBytes();

            byte[] msgbuf = { 0x0, 0x1, 0x2, 0x3 };

            PacketBuf test = new PacketBuf();
            List<byte[]> sendbuf = test.GetPacket(srcport, dstport, srcip, dstip, srcmac, dstmac, msgbuf);

            netdev.Open();
            for (int i = 0; i < 10; i++)
            {
                foreach (byte[] x in sendbuf)
                {
                    netdev.SendPacket(x);
                }
                System.Threading.Thread.Sleep(1000 * 3);
            }
        }
    }
}
