
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.*;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.event.*;
import java.nio.charset.StandardCharsets;
import java.util.Vector;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 主类
 */
public class Main {
    /* 抓包选项 */
    public static String selectedOption;
    /* 现在是否正在抓包 */
    public static volatile boolean isCapturing = true;
    public static void main(String[] args) {
        Main mainObj = new Main();
        /* 开窗口 */
        NPCWindow window = new NPCWindow();
        try {
            /* 获取网络接口列表 */
            NetworkInterface[] devices = JpcapCaptor.getDeviceList();

            /* 创建线程池，避免为同一个接口创建多个线程 */
            ExecutorService threadPool = Executors.newFixedThreadPool(devices.length);

            /* 没找到本机的网络设备 */
            if (devices.length == 0) {
                System.out.println("未找到网络设备");
                return;
            }

            /* 将网络接口名称添加到 JComboBox 中 */
            for (NetworkInterface device : devices) {
                window.chooseDevice.addItem(device.name + " - " + device.description);
            }

            /* 设置选项监听器, 获取选项框被选中的选项 */
            window.chooseDevice.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    isCapturing = false;
                    NPCWindow.statusArea.setText("加载接口，当前抓包暂停中...");
                    JComboBox<String> comboBox = (JComboBox<String>) e.getSource();
                    selectedOption = (String) comboBox.getSelectedItem();
                }
            });
            /* 根据被选中的选项来对特定接口进行抓包 */
            window.startBtn.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    for (NetworkInterface device : devices) {
                        if (selectedOption.equals(device.name + " - " + device.description) || selectedOption.equals("all")) {
                            // 改变这个值使得当前线程可以结束
                            isCapturing = false;
                            if (!selectedOption.equals("all")) {
                                // 等待一段时间，以确保之前的抓包线程能够结束
                                try {
                                    Thread.sleep(1000); // 1秒钟
                                } catch (InterruptedException ex) {
                                    ex.printStackTrace();
                                }
                            }

                            // 提交任务给线程池执行
                            threadPool.submit(() -> mainObj.NetworkPacketCap(device));
                        }
                    }
                }
            });
            /* 清空屏幕 */
            window.clearBtn.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    mainObj.clearTable();
                }
            });
            /* 根据选中的表格条目，来显示特定的包的payload */
            NPCWindow.table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
                @Override
                public void valueChanged(ListSelectionEvent e) {
                    if (!e.getValueIsAdjusting()) {
                        int selectedRow = NPCWindow.table.getSelectedRow();
                        if (selectedRow != -1) {
                            // 获取选中行的某一列的数据
                            String dataByte = (String) NPCWindow.model.getValueAt(selectedRow, 6);
                            String dataStr = (String) NPCWindow.model.getValueAt(selectedRow, 7);

                            NPCWindow.byteArea.setText(dataByte);
                            NPCWindow.txtArea.setText(dataStr);
                        }
                    }
                }
            });

            // 在程序退出时执行的关闭逻辑
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                if (threadPool != null && !threadPool.isShutdown()) {
                    threadPool.shutdown(); // 关闭线程池
                }
            }));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    /**
     * 清空表项
     */
    private void clearTable() {
        NPCWindow.model.setRowCount(0);
        NPCWindow.byteArea.setText("");
        NPCWindow.txtArea.setText("");
    }
    /**
     * 对单独一个网络接口进行抓包
     * @param device 网络接口
     */
    private void NetworkPacketCap(NetworkInterface device) {
        System.out.println("This is Thread: " + Thread.currentThread());
        isCapturing = true;
        clearTable();
        try {
            // 打开网卡连接, 捕获时长为1s，默认开启混杂模式
            JpcapCaptor jpcapCaptor = JpcapCaptor.openDevice(device, 65535, true, 1000);
            if (selectedOption.equals("all")) {
                SwingUtilities.invokeLater(() -> NPCWindow.statusArea.setText("当前接口：所有接口，抓包中..."));
            } else {
                NPCWindow.statusArea.setText("当前接口：" + device.name + "-" + device.description + " 抓包中...");
            }

            while (isCapturing) {
                jpcapCaptor.processPacket(1, new PacketHandler());
            }
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
        String filterInput = NPCWindow.getFilterField().getText();
        // 分析IP包
        if (packet.getClass().equals(IPPacket.class)) {
            // IP数据包, IPPacket类继承 Packet类,包括 IPV4和 IPV6;
            IPPacket ipPacket = (IPPacket) packet;

            if (filterInput.equals("SRC" + ipPacket.src_ip.toString()) ||
                filterInput.equals("DST" + ipPacket.dst_ip.toString()) ||
                filterInput.equals("IP") ||
                filterInput.isEmpty()) {
                // 数据部分
                byte[] dataByte = ipPacket.data;
                String hex = this.toHexString(dataByte);
                String str = this.toCharString(dataByte);
                // 时间戳
                double time = (double) ipPacket.sec + (double) ipPacket.usec / 1000;
                String timeStr = String.format("%.2f", time);
                // 源ip，目的ip
                String srcAddress = ipPacket.src_ip.toString();
                String dstAddress = ipPacket.dst_ip.toString();
                // 协议
                String pro = "IP";
                // 长度
                String len = String.valueOf(ipPacket.data.length);
                // 信息
                String info = "TTL: " + ipPacket.hop_limit + " " + "Identification: " + ipPacket.ident + "Version: " + " " + ipPacket.version;
                // 加入table
                addToTable(timeStr, srcAddress, dstAddress, pro, len, info, hex, str);

                System.out.println("ip data: " + hex);
                System.out.println("data: " + str);
            }
        }
        // 分析TCP包
        if (packet.getClass().equals(TCPPacket.class)) {
            TCPPacket tcpPacket = (TCPPacket) packet;

            if (filterInput.equals("SRC" + tcpPacket.src_ip.toString()) ||
                    filterInput.equals("DST" + tcpPacket.dst_ip.toString()) ||
                    filterInput.equals("TCP") ||
                    filterInput.isEmpty()) {
                // 数据部分
                byte[] dataByte = tcpPacket.data;
                String hex = this.toHexString(dataByte);
                String str = this.toCharString(dataByte);
                // 时间戳
                double time = (double) tcpPacket.sec + (double) tcpPacket.usec / 1000000.0;
                String timeStr = String.format("%.2f", time);
                // 源ip，目的ip
                String srcAddress = tcpPacket.src_ip.toString();
                String dstAddress = tcpPacket.dst_ip.toString();
                // 协议
                String pro = "TCP";
                // 长度
                String len = String.valueOf(tcpPacket.data.length);
                // 信息
                String info = "ACK= " + tcpPacket.ack_num + ", " + "SEQ= " + tcpPacket.sequence + ", " + "DST_PORT: " + tcpPacket.dst_port + ", " + "SRC_PORT: " + tcpPacket.src_port;
                // 加入table
                addToTable(timeStr, srcAddress, dstAddress, pro, len, info, hex, str);

                System.out.println("tcp data: " + hex);
                System.out.println("data: " + str);
            }
        }
        // 分析UDP包
        if (packet.getClass().equals(UDPPacket.class)) {
            // UDP数据包
            UDPPacket udpPacket = (UDPPacket) packet;

            if (filterInput.equals("SRC" + udpPacket.src_ip.toString()) ||
                    filterInput.equals("DST" + udpPacket.dst_ip.toString()) ||
                    filterInput.equals("UDP") ||
                    filterInput.isEmpty()) {
                // 数据部分
                byte[] dataByte = udpPacket.data;
                String hex = this.toHexString(dataByte);
                String str = this.toCharString(dataByte);
                // 时间戳
                double time = (double) udpPacket.sec + (double) udpPacket.usec / 1000;
                String timeStr = String.format("%.2f", time);
                // 源ip，目的ip
                String srcAddress = udpPacket.src_ip.toString();
                String dstAddress = udpPacket.dst_ip.toString();
                // 协议
                String pro = "UDP";
                // 长度
                String len = String.valueOf(udpPacket.data.length);
                // 信息
                String info = "protocol: " + inferProtocol(udpPacket.src_port, udpPacket.dst_port, str) + ", " + "DST_PORt " + udpPacket.dst_port + ", " + "SRC_PORT: " + udpPacket.src_port;
                // 加入table
                addToTable(timeStr, srcAddress, dstAddress, pro, len, info, hex, str);

                System.out.println("udp data: " + hex);
                System.out.println("data: " + str);
            }
        }
    }

    /**
     * 为表格添加一行元素
     * @param time 时间戳
     * @param srcip 源ip
     * @param dstip 目的ip
     * @param pro 协议
     * @param len 长度
     * @param info 信息
     */
    public void addToTable(String time, String srcip, String dstip, String pro, String len, String info, String dataByte, String dataStr) {
        Vector<String> dataVec = new Vector<String>();
        dataVec.add(time);
        dataVec.add(srcip);
        dataVec.add(dstip);
        dataVec.add(pro);
        dataVec.add(len);
        dataVec.add(info);
        dataVec.add(dataByte);
        dataVec.add(dataStr);
        // 将更新表格数据任务添加进事件调度线程的队列中等待执行
        SwingUtilities.invokeLater(() -> {
            NPCWindow.model.addRow(dataVec);
        });
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
    /**
     *
     * @param sourcePort 源端口
     * @param destinationPort 目的端口
     * @param str 报文
     * @return 协议
     */
    public String inferProtocol(int sourcePort, int destinationPort, String str) {
        // 通过端口号来推断应用协议
        if (sourcePort == 443 || destinationPort == 443 || str.contains("HTTPS")) {
            return "HTTPS";
        } else if (sourcePort == 80 || destinationPort == 80 || str.contains("HTTP")) {
            return "HTTP";
        } else if (sourcePort == 53 || destinationPort == 53) {
            return "DNS";
        } else {
            return "Unknown";
        }
    }
}