using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Reflection;

namespace Utility
{
	/// <summary>
	/// 序列化和反序列化类
	/// </summary>
	public class SerializeHelper
	{
        /// <summary>
        /// 结构体对象转为字节数组
        /// </summary>
        /// <param name="structType">结构体类型</param>
        /// <param name="isbigendian">大小端模式,默认大端</param>
        /// <returns></returns>
        public static byte[] StructToBytes(object structure, bool isbigendian = true)
        {
            int size = Marshal.SizeOf(structure);
            IntPtr buffer = Marshal.AllocHGlobal(size);

            try
            {
                Marshal.StructureToPtr(structure, buffer, false);
                byte[] bytes = new byte[size];
                Marshal.Copy(buffer, bytes, 0, size);

                if (true == isbigendian)
                {
                    object obj = Marshal.PtrToStructure(buffer, structure.GetType());
                    int reverseoffset = 0;
                    foreach (FieldInfo x in obj.GetType().GetFields())
                    {
                        object value = x.GetValue(obj);
                        TypeCode typecode = Type.GetTypeCode(value.GetType());
                        switch(typecode)
                        {
                            case TypeCode.Char:
                            case TypeCode.Byte:
                                {
                                    reverseoffset += Marshal.SizeOf(value);
                                    break;
                                }
                            case TypeCode.Single:
                                break;
                            case TypeCode.Int16:
                            case TypeCode.UInt16:
                            case TypeCode.Int32:
                            case TypeCode.UInt32:
                            case TypeCode.Int64:
                            case TypeCode.UInt64:
                                {
                                    Array.Reverse(bytes, reverseoffset, Marshal.SizeOf(value));
                                    reverseoffset += Marshal.SizeOf(value);
                                    break;
                                }
                            case TypeCode.Object:
                                {
                                    reverseoffset += ((byte[])value).Length;
                                    break;
                                }
                            default:
                                break;
                        }
                    }
                }
                return bytes;
            }
            catch
            {
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
	}
}
