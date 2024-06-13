# 开发工具

- Windows 11
- IntelliJ IDEA 2023.2.1
- jpcap

# 设计思路及使用说明

## 基于多线程的网络抓包程序的实现思路

1. 获取网络接口列表，以网络接口为单位进行抓包。
2. 创建线程池，每个线程代表一个网络接口和一个分析包的线程，线程池容量就等于网络接口数量+1。
3. 根据用户选中的接口，执行线程池里面的线程进行抓包，将抓到的包存入一个队列。
4. 分析线程对队列里面抓到的包进行逐个处理、分析，目前仅支持分析IP、TCP、UDP三种包。
5. 其中，每次用户点击开始抓包按钮，都会从线程池取出一个用于抓包的线程；但是分析包的线程只有在程序启动的时候创建，这个线程将处理整个程序运行过程中抓到的全部包

## 图形化界面的设计及使用介绍

![](https://cdn.jsdelivr.net/gh/Easter1995/blog-image/202406051945179.png)

布局如图所示，现介绍使用方法：

- choose device：

  - 为一个选项框，里面列出了获取到的所有网络接口。
  - 选择一个选项可以对特定接口进行抓包，选择all表示对全部接口进行抓包；选择choose a device表示先暂停不抓包。
  - 选择选项的时候抓包处于暂停状态

- start按钮：

  - 点击start后程序会先清除当前抓到的所有包的记录，然后对所选接口进行抓包。

- clear按钮：

  - 清除抓包记录

- filter：

  - 过滤器，要求输入大写字符串
  - 目前仅支持输入IP、TCP、UDP、SRC+IP地址、DST+IP地址。分别表示只抓某个类型的包和只抓源/目的为指定IP地址的包
  - 输入过滤条件之后要重新选择接口并按start，过滤条件才可生效

- 抓包展示表格部分：

  - time stamp：表示时间戳，保留两位小数单位为ms
  - src ip：表示源IP地址
  - dst ip：表示目的IP地址
  - protocol：表示协议类型
  - length：表示包数据部分的长度
  - info：表示包的重要信息
    - IP：TTL、identification、version
    - TCP：ACK、SEQ、DST_PORT、SRC_PORT
    - UDP：上层协议、DST_IP、SRC_PORT

- 选中某个包会展示详细数据信息：

  - hex bytes：包数据部分的16进制表示
  - string：包数据部分的字符表示，如果有ASCII编码无法解析的就用“.”表示

- status：表示抓包状态，分为 “加载接口，当前抓包暂停中...” 和 “当前接口：[接口信息]，抓包中...”

- 抓包示例：

  - 设置全部接口抓包
  - 设置只抓UDP包

  ![image-20240605200146032](https://cdn.jsdelivr.net/gh/Easter1995/blog-image/202406052001271.png)

# 类功能介绍

## public class Main

这是主类，其作用有：

- 显示窗口
- 获取网络接口
- 创建线程池、执行线程、退出程序时关闭线程池
  - 其中线程包括抓包的线程：如果选择了全部的网卡，就一个网卡对应一个线程进行抓包
  - 包括了处理包的线程

- 监听用户与图形界面的交互，并作出相应反应

全局变量：

- public static String selectedOption：表示用户在filter输入的内容，因为设置为全局变量，因此如果在抓包过程中改变这个值也是支持的
- public static volatile boolean isRunning：表示程序是否结束，初始为true，在程序退出时执行的关闭逻辑被设为false，目的是保证执行AnalyzePacket()任务的线程安全退出
- public static BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>()：存包的队列，保证全局且线程安全 

监听器：

- window.chooseDevice.addActionListener：监听用户选的网卡是哪个
- window.startBtn.addActionListener：监听用户是否点击开始按钮，根据用户选择的网卡从线程池启动线程
- window.clearBtn.addActionListener：监听用户是否要清空屏幕
- NPCWindow.table.getSelectionModel().addListSelectionListener：根据用户选择的表项（包），来显示包的数据部分的字节和字符串
- Runtime.getRuntime().addShutdownHook：启动一个新线程用于执行程序退出的逻辑，使用 shutdown 和 awaitTermination 来优雅地关闭线程池，确保所有线程在程序关闭时正确终止

函数：

- private void clearTable()
  - 当用户点击clear按钮时清空抓包展示表项
  - 清空packetQueue
- private void AnalyzePacket()
  - 用来分析包的函数
  - 将packetQueue里面的包取出来进行分析

- private void NetworkPacketCap(NetworkInterface device)
  - 对device这个网络接口进行抓包，将抓到的包放入packetQueue
  - 显示status的信息

## class PacketHandler implements PacketReceiver

这是用于抓包、处理包的类，与Main在同一个包内，其作用有：

- 抓包
- 根据包的类型处理包
- 将处理包得到的信息显示在图形化界面上
- 将包里面的二进制流转换为16进制和String

函数：

- public void receivePacket (Packet packet)
  - 取得filter里面的字段，并根据过滤条件来过滤包
  - 对每个包单独处理，获取包展示表项需要的所有信息并将其加入表的数据集
  - 在控制台打印出包数据部分的16进制和String
- public void addToTable(String time, String srcip, String dstip, String pro, String len, String info, String dataByte, String dataStr)
  - 为包展示表格添加一行表项，表项内容即为传入的参数
- public String toCharString(byte[] dataByte)
  - 将包的数据部分由二进制字节数组转换为String
- public String toHexString(byte[] dataByte)
  - 将包的数据部分由二进制字节数组转换为16进制字符串
- public String inferProtocol(int sourcePort, int destinationPort, String str)
  - 根据源端口和目标端口推断包的上层协议
  - 目前仅能知道HTTP、HTTPS、DNS三种

## public class NPCWindow extends JFrame

`JFrame`是Java Swing库中的一个类，用于创建图形用户界面（GUI）应用程序的顶层窗口。NPCWindow是它的子类

作用：构造、整合图形化界面

函数

- public NPCWindow()
  - 显示图形化窗口
- public static JTextField getFilterField()
  - 获取filter示例
- public void createNewWindow()
  - 构造窗口
  - 规定窗口大小
  - 将窗口的各个部分整合在一起，包括之前图示中的所有部分

## class PanelStyle

用于设置图形化窗口各个部件的类，与NPCWindow在同一个包内

作用：详细设置图形化界面的每个部分

函数：

- public void setTopPanel(NPCWindow window)
  - 设置顶部面板的样式
    - 创建choose a device选项框并规定它的长度和内容
    - 创建start、clear按钮并规定它的长度
    - 创建filter输入框并规定它的长度
- public void setTablePanel(int windowWidth)
  - 设置中间显示包信息的表格的样式
    - 展示表头
    - 调整表格每一列的宽度
    - 实现当表格长度超出设置长度时，自动显示滚动条
- public void setBottomPanel(int windowSize)
  - 设置16进制码区域和字符区域的样式
    - 设置显示区域的大小和布局
    - 实现当字符过多时，自动显示滚动条
- public void setStatusPanel(int windowSize)
  - 设置状态区域的位置和大小
- 其余函数用于获取这个类的成员，也就是图形化界面的部件

# 类之间的联系

- NPCWindow类通过获取由PanelStyle类创建的图形化界面实例，将每个实例添加到JFrame实例，来显示整个图形化界面

- NPCWindow实例通过Main类来创建，因此最终图形化界面得以展示。

- Main类创建线程和窗口、监听用户动作

  - 如果选择了对所有的网卡进行抓包，就从线程池为每一个网卡分配一个线程，该线程执行mainObj.NetworkPacketCap(device)函数，表示对该device进行抓包。这个线程的主要作用就是抓包，并且将抓到的包放入线程安全的队列packetQueue

  - 创建分析包的线程，该线程只有在用户启动程序时创建，在程序退出时被回收。这个线程的主要作用就是取出packetQueue里面的包，并将其交给PacketHandler类来分析包。相当于所有抓包线程抓到的包都将由这一个线程来处理。

  - 最核心的就是这段代码：

    ```java
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
    
    // 创建处理包的线程
    threadPool.submit(() -> mainObj.AnalyzePacket());
    ```

- 而在PacketHandler中，将对每个抓到的包进行具体的处理。并且PacketHandler类获取图形化界面展示包信息需要的数据，并通过Java Swing库提供的方法将数据动态地加入图形化界面，从而使得最终数据的展示得以实现并且是动态的。