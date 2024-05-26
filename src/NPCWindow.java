
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;

/**
 * 负责可视化界面的类
 */
public class NPCWindow extends JFrame {
    private static DefaultTableModel model;
    private static JTextField filterField;
    private JTextArea showArea;
    private JButton startBtn;
    private JButton checkDeviceBtn;
    private JButton exitBtn;
    private JButton clearBtn;

    /**
     * 窗口的构造方法
     */
    public NPCWindow() {
        super();
        createNewWindow();
        setVisible(true);
    }
    /**
     * 新建窗口
     */
    public void createNewWindow() {
        /* 窗口基础设置 */
        setSize(1300, 800);
        setTitle("Network Packet Capture");
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
    }
}
