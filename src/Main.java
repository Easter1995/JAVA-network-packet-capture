
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.*;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 主类
 */
public class Main {
    public static void main(String[] args) {
        /* 开窗口 */
        new NPCWindow();
        try {
            /* 获取网络接口列表 */
            NetworkInterface[] devices = JpcapCaptor.getDeviceList();

            /* 没找到本机的网络设备 */
            if (devices.length == 0) {
                System.out.println("未找到网络设备");
                return;
            }

            /* 创建线程池，对每个网络接口进行抓包 */
            ExecutorService threadPool = Executors.newFixedThreadPool(devices.length);
            for (NetworkInterface device : devices) {
                Runnable task = () -> NetworkPacketCap(device);
                threadPool.execute(task);
            }
            /* 关闭线程池 */
            threadPool.shutdown();
            threadPool.shutdownNow();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 对单独一个网络接口进行抓包
     * @param device 网络接口
     */
    private static void NetworkPacketCap(NetworkInterface device) {
        System.out.println("This is Thread: " + Thread.currentThread());
        try {
            // 打开网卡连接, 捕获时长为1s，默认开启混杂模式
            JpcapCaptor jpcapCaptor = JpcapCaptor.openDevice(device, 65535, true, 1000);
            jpcapCaptor.processPacket(5, new PacketHandler());
            // 关闭捕获器，释放资源
            jpcapCaptor.close();
        } catch (Exception e) {
            // 异常处理
            System.out.println("catch exception in thread" + Thread.currentThread());
        }
    }
}


/**
 * 处理整个抓包+分析操作的类
 */
class PacketHandler implements PacketReceiver {
    /**
     * @param packet 要进行处理的包
     * 接收到包后进行处理的函数
     * **/
    @Override
    public void receivePacket (Packet packet) {
        // 分析IP包
        if (packet.getClass().equals(IPPacket.class)) {
            // IP数据包, IPPacket类继承 Packet类,包括 IPV4和 IPV6;
            IPPacket ipPacket = (IPPacket) packet;
            // 数据部分
            byte[] dataByte = ipPacket.data;
            String hex = this.toHexString(dataByte);
            String str = this.toCharString(dataByte);

            System.out.println("ip data: " + hex);
            System.out.println("data: " + str);
        }
        // 分析TCP包
        if (packet.getClass().equals(TCPPacket.class)) {
            // IP数据包, IPPacket类继承 Packet类,包括 IPV4和 IPV6;
            TCPPacket tcpPacket = (TCPPacket) packet;
            // 数据部分
            byte[] dataByte = tcpPacket.data;
            String hex = this.toHexString(dataByte);
            String str = this.toCharString(dataByte);

            System.out.println("tcp data: " + hex);
            System.out.println("data: " + str);
        }
        // 分析UDP包
        if (packet.getClass().equals(UDPPacket.class)) {
            // UDP数据包
            UDPPacket udpPacket = (UDPPacket) packet;
            // 数据部分
            byte[] dataByte = udpPacket.data;
            String hex = this.toHexString(dataByte);
            String str = this.toCharString(dataByte);

            System.out.println("udp data: " + hex);
            System.out.println("data: " + str);
        }
    }
    /**
     * 将字节数组转换为 utf-8 编码的字符串，只转换能转换的字符
     * @param dataByte 要进行转换的原始字节数组
     * **/
    public String toCharString(byte[] dataByte) {
        char[] charArray = new char[dataByte.length];
        for (int i = 0; i < dataByte.length; i++) {
            // 将字节转换为无符号数
            int unsignedIntValue = dataByte[i] & 0xFF;
            if (unsignedIntValue >= 32 && unsignedIntValue <= 126) {
                // 将无符号数转换为字符
                charArray[i] = (char) unsignedIntValue;
            } else {
                charArray[i] = '.';
            }
        }
        // 将字符数组转换为字节数组
        byte[] byteArray = new String(charArray).getBytes(StandardCharsets.UTF_8);
        // 使用 UTF-8 编码将字节数组转换为字符串
        return new String(byteArray, StandardCharsets.UTF_8);
    }

    /**
     * 将字节数组转换为十六进制数，1 字节为一组
     * @param dataByte 要进行转换的原始字节数组
     */
    public String toHexString(byte[] dataByte) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : dataByte) {
            // 将每个字节转换为十六进制，并追加到字符串中
            hexString.append(String.format("%02X ", b));
        }
        return hexString.toString();
    }
}