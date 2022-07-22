using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Net;
using System.Net.Sockets;
using Utility;

namespace UdpPacket
{
    public class PacketBuf
    {
        #region 私有变量
        private int _mtu = 1500;
        #endregion

        public List<byte[]> GetPacket(ushort srcport, ushort desport, byte[] srcip, byte[] dstip, byte[] srcmac, byte[] dstmac, byte[] msgbuf)
        {
            List<byte[]> packetbuf = new List<byte[]>();

            // 组udp数据包
            byte[] udppacket = UdpPacket(srcport, desport, msgbuf);

            // 组ip数据包，v4上层的udp校验和默认，v6添加
            IPAddress addr = new IPAddress(srcip);
            if (AddressFamily.InterNetwork == addr.AddressFamily)
            {
                // IPv4协议下，UDP的检验和字段可默认0，效率考虑先注掉
                // udppacket = IPv4UdpChecksum(srcip, dstip, udppacket);

                List<byte[]> ippacket = IPv4Packet(srcip, dstip, udppacket);
                packetbuf = MacPacket(srcmac, dstmac, 0x0800, ippacket);
            }
            else
            {
                udppacket = IPv6UdpChecksum(srcip, dstip, udppacket);

                List<byte[]> ippacket = IPv6Packets(srcip, dstip, udppacket);
                packetbuf = MacPacket(srcmac, dstmac, 0x86dd, ippacket);
            }

            return packetbuf;
        }

        #region UDP传输层
        /// <summary>
        /// 组udp包
        /// </summary>
        /// <param name="srcport">源端口</param>
        /// <param name="desport">目的端口</param>
        /// <param name="apppacket">数据消息</param>
        /// <returns></returns>
        private byte[] UdpPacket(ushort srcport, ushort desport, byte[] apppacket)
        {
            byte[] temp = new byte[Marshal.SizeOf(typeof(UDPHeader)) + apppacket.Length];

            UDPHeader udpheader = new UDPHeader()
            {
                SrcPort = srcport,
                DesPort = desport,
                Checksum = 0,
                Length = (ushort)(Marshal.SizeOf(typeof(UDPHeader)) + apppacket.Length)
            };
            byte[] udpheaderpacket = SerializeHelper.StructToBytes(udpheader);
            Buffer.BlockCopy(udpheaderpacket, 0, temp, 0, udpheaderpacket.Length);
            Buffer.BlockCopy(apppacket, 0, temp, udpheaderpacket.Length, apppacket.Length);

            return temp;
        }

        private byte[] IPv4UdpChecksum(byte[] srcaddress, byte[] dstaddress, byte[] udppacket)
        {
            byte[] temp = new byte[Marshal.SizeOf(typeof(IPv4UdpHeader)) + udppacket.Length];

            //byte[] srcbyte = srcaddress.GetAddressBytes();
            //byte[] dstbyte = dstaddress.GetAddressBytes();
            Array.Reverse(srcaddress);
            Array.Reverse(dstaddress);
            IPv4UdpHeader ipheader = new IPv4UdpHeader()
            {
                SrcAddress = BitConverter.ToUInt32(srcaddress, 0),
                DestAddress = BitConverter.ToUInt32(dstaddress, 0),
                Reserved = 0,
                Protocol = 17,
                Length = (ushort)udppacket.Length
            };
            byte[] ipv4udpheader = SerializeHelper.StructToBytes(ipheader);
            Buffer.BlockCopy(ipv4udpheader, 0, temp, 0, ipv4udpheader.Length);
            Buffer.BlockCopy(udppacket, 0, temp, ipv4udpheader.Length, udppacket.Length);

            // 校验
            ushort checksum = Checksum(temp);
            Buffer.BlockCopy(BitConverter.GetBytes(checksum), 0, udppacket, 6, 2);
            return udppacket;
        }

        private byte[] IPv6UdpChecksum(byte[] srcaddress, byte[] dstaddress, byte[] udppacket)
        {
            byte[] temp = new byte[Marshal.SizeOf(typeof(IPv6UdpHeader)) + udppacket.Length];

            //byte[] srcbyte = srcaddress.GetAddressBytes();
            //byte[] dstbyte = dstaddress.GetAddressBytes();
            IPv6UdpHeader ipheader = new IPv6UdpHeader()
            {
                SrcAddress = srcaddress,
                DestAddress = dstaddress,
                PayloadLen = (uint)udppacket.Length,
                Reserved = new byte[] { 0x00, 0x00, 0x00 },
                NextHeader = 17
            };
            byte[] ipv6udpheader = SerializeHelper.StructToBytes(ipheader);
            Buffer.BlockCopy(ipv6udpheader, 0, temp, 0, ipv6udpheader.Length);
            Buffer.BlockCopy(udppacket, 0, temp, ipv6udpheader.Length, udppacket.Length);

            // 校验
            ushort checksum = Checksum(temp);
            Buffer.BlockCopy(BitConverter.GetBytes(checksum), 0, udppacket, 6, 2);
            return udppacket;
        }
        #endregion

        #region IPv4网络层
        /// <summary>
        /// 组ip包
        /// </summary>
        /// <param name="srcaddress">源ip地址</param>
        /// <param name="dstaddress">目的ip地址</param>
        /// <param name="udppacket">传输层数据消息</param>
        /// <returns></returns>
        private List<byte[]> IPv4Packet(byte[] srcaddress, byte[] dstaddress, byte[] udppacket)
        {
            List<byte[]> temps = new List<byte[]>();

            // 分片判断
            if (_mtu - Marshal.SizeOf(typeof(IPv4Header)) < udppacket.Length)
            {
                temps = IPv4Fragments(srcaddress, dstaddress, udppacket);
            }
            else
            {
                byte[] temp = new byte[Marshal.SizeOf(typeof(IPv4Header)) + udppacket.Length];

                byte[] ipv4header = IPv4Header((ushort)udppacket.Length, 0, 0, srcaddress, dstaddress);
                Buffer.BlockCopy(ipv4header, 0, temp, 0, ipv4header.Length);
                Buffer.BlockCopy(udppacket, 0, temp, ipv4header.Length, udppacket.Length);

                temps.Add(temp);
            }
            return temps;
        }

        private byte[] IPv4Header(ushort transmitlen, ushort flags, ushort offset, byte[] srcaddress, byte[] dstaddress)
        {
            //byte[] srcbyte = srcaddress.GetAddressBytes();
            //byte[] dstbyte = dstaddress.GetAddressBytes();
            Array.Reverse(srcaddress);
            Array.Reverse(dstaddress);

            IPv4Header ipheader = new IPv4Header()
            {
                VersionAndHeaderLen = 0x45,
                TypeOfService = 0,
                TotalLen = (ushort)(Marshal.SizeOf(typeof(IPv4Header)) + transmitlen),
                Identification = 0,
                FragmentOffset = (ushort)((ushort)(flags << 13) | (ushort)(offset >> 3)),
                TimeToLive = 64,
                Protocol = 17,
                HeaderChecksum = 0,
                SrcAddress = BitConverter.ToUInt32(srcaddress, 0),
                DestAddress = BitConverter.ToUInt32(dstaddress, 0)
            };
            byte[] buffer = SerializeHelper.StructToBytes(ipheader);

            // 计算校验和
            ushort checksum = Checksum(buffer);
            Buffer.BlockCopy(BitConverter.GetBytes(checksum), 0, buffer, 10, 2);
            return buffer;
        }

        private List<byte[]> IPv4Fragments(byte[] srcaddress, byte[] dstaddress, byte[] udppacket)
        {
            List<byte[]> temps = new List<byte[]>();

            List<byte[]> fragmentbuf = IPv4FragmentCount(udppacket);
            ushort fragmentoffset = 0;
            foreach (byte[] x in fragmentbuf)
            {
                byte[] temp = new byte[Marshal.SizeOf(typeof(IPv4Header)) + x.Length];

                // IP分片时,标志位最后一片不同
                byte[] ipv4header = null;
                if (x != fragmentbuf[fragmentbuf.Count - 1])
                {
                    ipv4header = IPv4Header((ushort)x.Length, 1, fragmentoffset, srcaddress, dstaddress);
                }
                else
                {
                    ipv4header = IPv4Header((ushort)x.Length, 0, fragmentoffset, srcaddress, dstaddress);
                }
                fragmentoffset += (ushort)x.Length;
                Buffer.BlockCopy(ipv4header, 0, temp, 0, ipv4header.Length);
                Buffer.BlockCopy(x, 0, temp, ipv4header.Length, x.Length);

                temps.Add(temp);
            }

            return temps;
        }

        private List<byte[]> IPv4FragmentCount(byte[] udppacket)
        {
            List<byte[]> fragmentbuf = new List<byte[]>();

            // 偏移量需要以8字节为单位,需要留余处理           
            int maxoffset = (int)Math.Floor((double)(_mtu - Marshal.SizeOf(typeof(IPv4Header))) / 8.0);
            int maxpayload = maxoffset * 8;

            int srcoffset = 0;
            while (udppacket.Length - srcoffset > maxpayload)
            {
                byte[] temp = new byte[maxpayload];

                Buffer.BlockCopy(udppacket, srcoffset, temp, 0, maxpayload);
                srcoffset += maxpayload;

                fragmentbuf.Add(temp);
            }
            byte[] last = new byte[udppacket.Length - srcoffset];
            Buffer.BlockCopy(udppacket, srcoffset, last, 0, last.Length);
            fragmentbuf.Add(last);

            return fragmentbuf;
        }
        #endregion

        #region IPv6网络层
        private List<byte[]> IPv6Packets(byte[] srcaddress, byte[] dstaddress, byte[] udppacket)
        {
            List<byte[]> temps = new List<byte[]>();

            // 分片判断
            if (_mtu - Marshal.SizeOf(typeof(IPv6Header)) < udppacket.Length)
            {
                temps = IPv6Fragments(srcaddress, dstaddress, udppacket);
            }
            else
            {
                byte[] temp = new byte[Marshal.SizeOf(typeof(IPv6Header)) + udppacket.Length];

                byte[] ipv6header = IPv6Header((ushort)udppacket.Length, 17, srcaddress, dstaddress);
                Buffer.BlockCopy(ipv6header, 0, temp, 0, ipv6header.Length);
                Buffer.BlockCopy(udppacket, 0, temp, ipv6header.Length, udppacket.Length);

                temps.Add(temp);
            }
            return temps;
        }

        private byte[] IPv6Header(ushort extenheadertransmitlen, byte nextheader, byte[] srcaddress, byte[] dstaddress)
        {
            //byte[] srcbyte = srcaddress.GetAddressBytes();
            //byte[] dstbyte = dstaddress.GetAddressBytes();

            IPv6Header ipheader = new IPv6Header()
            {
                Service = 0x63000000,
                PayloadLen = extenheadertransmitlen,
                NextHeader = nextheader,
                HopLimit = 64,
                SrcAddress = srcaddress,
                DestAddress = dstaddress
            };
            byte[] buffer = SerializeHelper.StructToBytes(ipheader);
            return buffer;
        }

        private byte[] IPv6FragmentHeader(ushort flags, ushort offset)
        {
            IPv6FragmentHeader ipv6fragment = new IPv6FragmentHeader()
            {
                NextHeader = 17,
                Reserved = 0,
                FragmentOffset = (ushort)(flags | offset),
                Identification = 0
            };
            byte[] buffer = SerializeHelper.StructToBytes(ipv6fragment);
            return buffer;
        }

        private List<byte[]> IPv6Fragments(byte[] srcaddress, byte[] dstaddress, byte[] udppacket)
        {
            List<byte[]> temps = new List<byte[]>();

            List<byte[]> fragmentbuf = IPv6FragmentCount(udppacket);
            ushort fragmentoffset = 0;
            foreach (byte[] x in fragmentbuf)
            {
                byte[] temp = new byte[Marshal.SizeOf(typeof(IPv6Header)) + Marshal.SizeOf(typeof(IPv6FragmentHeader)) + x.Length];

                byte[] ipv6header = IPv6Header((ushort)(x.Length + Marshal.SizeOf(typeof(IPv6FragmentHeader))), 44, srcaddress, dstaddress);
                byte[] fragmentheader = null;
                if (x != fragmentbuf[fragmentbuf.Count - 1])
                {
                    fragmentheader = IPv6FragmentHeader(1, fragmentoffset);
                }
                else
                {
                    fragmentheader = IPv6FragmentHeader(0, fragmentoffset);
                }
                fragmentoffset += (ushort)x.Length;
                Buffer.BlockCopy(ipv6header, 0, temp, 0, ipv6header.Length);
                Buffer.BlockCopy(fragmentheader, 0, temp, ipv6header.Length, fragmentheader.Length);
                Buffer.BlockCopy(x, 0, temp, ipv6header.Length + fragmentheader.Length, x.Length);

                temps.Add(temp);
            }
            return temps;
        }

        private List<byte[]> IPv6FragmentCount(byte[] udppacket)
        {
            List<byte[]> fragmentbuf = new List<byte[]>();

            int maxoffset = (int)Math.Floor((double)(_mtu - Marshal.SizeOf(typeof(IPv6Header)) - Marshal.SizeOf(typeof(IPv6FragmentHeader))) / 8.0);
            int maxpayload = maxoffset * 8;

            int srcoffset = 0;
            while (udppacket.Length - srcoffset > maxpayload)
            {
                byte[] temp = new byte[maxpayload];

                Buffer.BlockCopy(udppacket, srcoffset, temp, 0, maxpayload);
                srcoffset += maxpayload;

                fragmentbuf.Add(temp);
            }
            byte[] last = new byte[udppacket.Length - srcoffset];
            Buffer.BlockCopy(udppacket, srcoffset, last, 0, last.Length);
            fragmentbuf.Add(last);

            return fragmentbuf;
        }
        #endregion

        #region 数据链路层
        private List<byte[]> MacPacket(byte[] srcaddress, byte[] dstaddress, ushort type, List<byte[]> ippacket)
        {
            List<byte[]> temps = new List<byte[]>();

            MacHeader macheader = new MacHeader()
            {
                DstAddress = dstaddress,
                SrcAddress = srcaddress,
                Type = type
            };
            byte[] macheaderpacket = SerializeHelper.StructToBytes(macheader);
            foreach (byte[] x in ippacket)
            {
                byte[] temp = new byte[Marshal.SizeOf(typeof(MacHeader)) + x.Length];
                Buffer.BlockCopy(macheaderpacket, 0, temp, 0, macheaderpacket.Length);
                Buffer.BlockCopy(x, 0, temp, macheaderpacket.Length, x.Length);

                temps.Add(temp);
            }

            return temps;
        }
        #endregion

        #region 校验和
        private ushort Checksum(byte[] buffer)
        {
            uint sum = 0;

            byte[] temp = null;
            if (0 != buffer.Length % 2)
            {
                temp = new byte[buffer.Length + 1];
                Buffer.BlockCopy(buffer, 0, temp, 0, buffer.Length);
            }
            else
            {
                temp = buffer;
            }

            int offset = 0;
            while (temp.Length > offset)
            {
                sum += BitConverter.ToUInt16(temp, offset);
                sum = (sum >> 16) + (sum & 0xffff);
                offset += 2;
            }
            return (ushort)(~sum);
        }
        #endregion
    }
}
