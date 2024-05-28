
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;

/**
 * 负责可视化界面的类
 */
public class NPCWindow extends JFrame {
    public static JTextField filterField;
    public static DefaultTableModel model;
    public static JTextArea byteArea;
    public static JTextArea txtArea;
    public static JTextArea statusArea;
    public static JTable table;
    public JComboBox<String> chooseDevice;
    public JButton startBtn;
    public JButton clearBtn;
    /**
     * 窗口的构造方法
     */
    public NPCWindow() {
        super();
        createNewWindow();
        setVisible(true);
    }

    /**
     * 获取filter实例
     * @return filter实例
     */
    public static JTextField getFilterField() {
        return filterField;
    }
    /**
     * 新建窗口
     */
    public void createNewWindow() {
        /* 窗口基础设置 */
        setSize(1250, 560);
        setTitle("Network Packet Capture");
        JPanel mainPanel = new JPanel();
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        /* 设置主面板 */
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        add(mainPanel);
        PanelStyle panelStyle = new PanelStyle();

        /* 窗口顶部 */
        panelStyle.setTopPanel(this);
        mainPanel.add(panelStyle.getTopPanel());

        /* 窗口主体 */
        panelStyle.setTablePanel(this.getWidth());
        mainPanel.add(panelStyle.getTablePanel());

        /* 添加间距 */
        mainPanel.add(Box.createVerticalStrut(10));

        /* 窗口底部 */
        panelStyle.setBottomPanel(this.getWidth());
        mainPanel.add(panelStyle.getBottomPanel());

        /* 状态栏 */
        panelStyle.setStatusPanel(this.getWidth());
        mainPanel.add(panelStyle.getStatusPanel());

        /* 添加间距 */
        mainPanel.add(Box.createVerticalStrut(10));

        pack();
    }
}

/**
 * 每个板块的样式
 */
class PanelStyle {
    // 最上面的导航栏
    private JPanel topPanel;
    // 主体
    private JPanel tablePanel;
    // 底部的数据部分
    private JPanel bottomPanel;
    // 当前状态
    private JPanel statusPanel;

    /**
     * 最上层的panel
     * @param window 窗口实例
     */
    public void setTopPanel(NPCWindow window) {
        topPanel = new JPanel();
        topPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        /* 顶部选择接口的组件 */
        window.chooseDevice = new JComboBox<String>(new String[]{"choose a device","all"});
        window.chooseDevice.setPrototypeDisplayValue("11111111111111111111111111111111111111111111111111111111111111111111111111111111111");
        /* start按钮 */
        window.startBtn = new JButton("start");
        /* clear按钮 */
        window.clearBtn = new JButton("clear");
        /* filter输入框 */
        JLabel filterLabel = new JLabel("filter: ");
        NPCWindow.filterField = new JTextField();
        NPCWindow.filterField.setPreferredSize(new Dimension(window.getWidth() - window.chooseDevice.getPreferredSize().width - window.startBtn.getPreferredSize().width - window.clearBtn.getPreferredSize().width - filterLabel.getPreferredSize().width, 28));
        topPanel.add(window.chooseDevice);
        topPanel.add(window.startBtn);
        topPanel.add(window.clearBtn);
        topPanel.add(filterLabel);
        topPanel.add(NPCWindow.filterField);
    }

    /**
     * 主面板的布局，包含抓包的表格条目
     * @param windowWidth 窗口宽度
     */
    public void setTablePanel(int windowWidth) {
        NPCWindow.model = new DefaultTableModel() {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // 不允许编辑任何单元格
            }
        };
        tablePanel = new JPanel();
        tablePanel.setMaximumSize(new Dimension(windowWidth, 270));
        tablePanel.setLayout(new BorderLayout()); // 使用边界布局管理器

        /* time stamp    |    source ip   |   dest ip   | pro | len |      info     | */
        String[] columnNames = {"time stamp", "source ip", "dest ip", "protocol", "length", "info", "bytes", "str"}; // 定义表格列名数组
        NPCWindow.table = new JTable(NPCWindow.model);
        DefaultTableModel model = (DefaultTableModel) NPCWindow.table.getModel();
        model.setColumnIdentifiers(columnNames);
        JScrollPane scrollPane = new JScrollPane(NPCWindow.table);
        NPCWindow.table.setEnabled(true);
        // 手动调整列宽度
        NPCWindow.table.getColumnModel().getColumn(0).setPreferredWidth(windowWidth * 2 / 24);
        NPCWindow.table.getColumnModel().getColumn(1).setPreferredWidth(windowWidth * 5 / 24);
        NPCWindow.table.getColumnModel().getColumn(2).setPreferredWidth(windowWidth * 5 / 24);
        NPCWindow.table.getColumnModel().getColumn(3).setPreferredWidth(windowWidth * 3 / 24);
        NPCWindow.table.getColumnModel().getColumn(4).setPreferredWidth(windowWidth * 3 / 24);
        NPCWindow.table.getColumnModel().getColumn(5).setPreferredWidth(windowWidth * 6 / 24);
        // 隐藏最后两列
        NPCWindow.table.getColumnModel().getColumn(6).setMaxWidth(0);
        NPCWindow.table.getColumnModel().getColumn(6).setMinWidth(0);
        NPCWindow.table.getColumnModel().getColumn(6).setWidth(0);
        NPCWindow.table.getColumnModel().getColumn(6).setResizable(false);
        NPCWindow.table.getColumnModel().getColumn(6).setPreferredWidth(0);
        NPCWindow.table.getColumnModel().getColumn(6).setHeaderValue(""); // 可选，清除列的标题

        NPCWindow.table.getColumnModel().getColumn(7).setMaxWidth(0);
        NPCWindow.table.getColumnModel().getColumn(7).setMinWidth(0);
        NPCWindow.table.getColumnModel().getColumn(7).setWidth(0);
        NPCWindow.table.getColumnModel().getColumn(7).setResizable(false);
        NPCWindow.table.getColumnModel().getColumn(7).setPreferredWidth(0);
        NPCWindow.table.getColumnModel().getColumn(7).setHeaderValue(""); // 可选，清除列的标题

        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED); // 根据需要显示垂直滚动条
        scrollPane.setPreferredSize(new Dimension(windowWidth, 270));
          // 在添加数据后，滚动条自动滚动到最后一行
//        NPCWindow.table.getModel().addTableModelListener(new TableModelListener() {
//            @Override
//            public void tableChanged(TableModelEvent e) {
//                SwingUtilities.invokeLater(new Runnable() {
//                    @Override
//                    public void run() {
//                        // 获取滚动条对象
//                        JScrollBar verticalScrollBar = scrollPane.getVerticalScrollBar();
//                        // 设置滚动条位置
//                        verticalScrollBar.setValue(verticalScrollBar.getMaximum());
//                    }
//                });
//            }
//        });
        tablePanel.add(scrollPane, BorderLayout.CENTER); // 将滚动面板添加到中间位置
    }

    /**
     * 下面的区域：16进制码区域和字符区域
     * @param windowSize 窗口大小
     * */
    public void setBottomPanel(int windowSize) {
        bottomPanel = new JPanel();
        bottomPanel.setPreferredSize(new Dimension(windowSize, 200));
        bottomPanel.setLayout(new BoxLayout(bottomPanel, BoxLayout.X_AXIS));
        NPCWindow.byteArea = new JTextArea();
        NPCWindow.txtArea = new JTextArea();

        NPCWindow.byteArea.setLineWrap(true);
        NPCWindow.txtArea.setLineWrap(true);

        NPCWindow.byteArea.setEditable(false);
        NPCWindow.txtArea.setEditable(false);

        // 设置 JTextArea 的首选大小
        NPCWindow.byteArea.setMaximumSize(new Dimension(windowSize / 2 - 15, 200));
        NPCWindow.txtArea.setMaximumSize(new Dimension(windowSize / 2 - 15, 200));

        JScrollPane byteScrollPane = new JScrollPane(NPCWindow.byteArea);
        JScrollPane txtScrollPane = new JScrollPane(NPCWindow.txtArea);
        byteScrollPane.setPreferredSize(new Dimension(windowSize / 2 - 15, 200));
        txtScrollPane.setPreferredSize(new Dimension(windowSize / 2 - 15, 200));

        byteScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        txtScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);

        // 将 JScrollPane 添加到 bottomPanel
        bottomPanel.add(Box.createHorizontalStrut(20));
        bottomPanel.add(byteScrollPane);
        bottomPanel.add(Box.createHorizontalStrut(10));
        bottomPanel.add(txtScrollPane);
        bottomPanel.add(Box.createHorizontalStrut(20));
    }
    public void setStatusPanel(int windowSize) {
        statusPanel = new JPanel();
        statusPanel.setLayout(new FlowLayout());
        NPCWindow.statusArea = new JTextArea();
        NPCWindow.statusArea.setLineWrap(true);
        NPCWindow.statusArea.setPreferredSize(new Dimension(windowSize, 70));

        statusPanel.add(Box.createHorizontalStrut(10));
        statusPanel.add(NPCWindow.statusArea);
        statusPanel.add(Box.createHorizontalStrut(10));
    }
    public JPanel getTopPanel() {
        return topPanel;
    }
    public JPanel getTablePanel() {
        return tablePanel;
    }
    public JPanel getBottomPanel() {
        return bottomPanel;
    }
    public JPanel getStatusPanel() {
        return statusPanel;
    }
}