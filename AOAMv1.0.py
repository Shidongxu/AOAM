import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu
import csv
import threading
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler, exceptions

class HuaweiSwitchManager:
    def __init__(self, root):
        self.root = root
        self.root.title("交换机管理工具（华为专版）--作者：小石头，尊重原创，请勿用于商业用途！")
        self.devices = []
        self.running_tasks = False
        self.log_queue = Queue()
        self._setup_ui()
        self._setup_connection_manager()
        self.root.after(100, self._update_log)

    def _setup_ui(self):
        """初始化用户界面"""
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 设备列表
        self.tree = ttk.Treeview(main_frame, columns=("IP", "用户名", "端口", "类型"), show="headings")
        self.tree.heading("IP", text="IP地址")
        self.tree.heading("用户名", text="用户名")
        self.tree.heading("端口", text="端口")
        self.tree.heading("类型", text="设备类型")
        self.tree.grid(row=0, column=0, columnspan=4, sticky="nsew", pady=5)
        # 绑定右击事件
        self.tree.bind("<Button-3>", self.on_tree_right_click)
        # 绑定鼠标左键点击事件
        self.tree.bind("<Button-1>", self.on_tree_click)
        # 设备列表滚动条
        self.tree_scrollbar = tk.Scrollbar(main_frame, command=self.tree.yview)
        self.tree_scrollbar.grid(row=0, column=4, sticky="ns")
        self.tree.config(yscrollcommand=self.tree_scrollbar.set)

        # 按钮区域
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=1, column=0, pady=5, sticky="w")
        
        self.import_btn = ttk.Button(btn_frame, text="导入设备", command=self.import_devices)
        self.test_btn = ttk.Button(btn_frame, text="测试连接", command=self.test_connections)
        self.run_btn = ttk.Button(btn_frame, text="执行命令", command=self.execute_commands)
        self.config_btn = ttk.Button(btn_frame, text="获取配置", command=self.get_configurations)
        self.clear_btn = ttk.Button(btn_frame, text="清空列表", command=self.clear_devices)
        self.about_author_btn = ttk.Button(btn_frame, text="关于作者", command=self.show_about_author)
        
        for btn in [self.import_btn, self.test_btn, self.run_btn, self.config_btn, self.clear_btn, self.about_author_btn]:
            btn.pack(side=tk.LEFT, padx=2)

        # 命令输入
        self.cmd_text = tk.Text(main_frame, height=8, width=70)
        self.cmd_text.grid(row=2, column=0, columnspan=4, sticky="nsew", pady=5)
        # 绑定FocusIn事件以清除默认文本
        self.cmd_text.bind("<FocusIn>", self._clear_placeholder)

        # 插入默认文本
        self._insert_placeholder()

        # 命令输入滚动条
        self.cmd_scrollbar = tk.Scrollbar(main_frame, orient='vertical', command=self.cmd_text.yview)
        self.cmd_scrollbar.grid(row=2, column=3, sticky='ns')
        self.cmd_text.config(yscrollcommand=self.cmd_scrollbar.set)

        # 日志输出
        self.log_text = tk.Text(main_frame, height=15, state='disabled')
        self.log_text.grid(row=3, column=0, columnspan=3, sticky="nsew")

        # 日志滚动条
        self.log_scrollbar = tk.Scrollbar(main_frame, command=self.log_text.yview)
        self.log_scrollbar.grid(row=3, column=3, sticky="ns")
        self.log_text.config(yscrollcommand=self.log_scrollbar.set)

        # 布局配置
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(3, weight=0)  # 确保滚动条不会占据太多空间
        main_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(2, weight=1)
        main_frame.rowconfigure(3, weight=1)
    def show_about_author(self):
        """显示关于作者的信息"""
        messagebox.showinfo("关于作者", "本工具由小石头开发，尊重原创，请勿用于商业用途！")
    def on_tree_click(self, event):
        """处理设备列表的点击事件"""
        # 检查点击的位置是否在项上
        item = self.tree.identify_row(event.y)
        if not item:
            # 如果不在项上，则取消所有选中项
            self.tree.selection_set()  # 取消选中所有项

    def on_tree_right_click(self, event):
        """处理设备列表的右击事件"""
        item = self.tree.identify_row(event.y)
        if item:
            selected_device = self.devices[self.tree.index(item)]
            self.show_right_click_menu(event, selected_device)

    def show_right_click_menu(self, event, device):
        """显示右击菜单"""
        menu = Menu(self.root, tearoff=0)
        menu.add_command(label="保存配置", command=lambda: self.save_configuration(device))
        menu.add_command(label="删除设备", command=lambda: self.delete_device(device))
        menu.post(event.x_root, event.y_root)

    def save_configuration(self, device):
        """保存设备配置到文件"""
        self.log("开始获取设备配置...", 'INFO')

        def run_config():
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self.conn_manager.get_configuration, device)
                try:
                    ip, config = future.result()
                    self.log(f"{ip} 配置信息已获取", 'INFO')
                    self.save_config_to_file(ip, config)
                except Exception as e:
                    self.log(f"配置获取失败: {str(e)}", 'ERROR')

        threading.Thread(target=run_config, daemon=True).start()
    def delete_device(self, device):
        """从列表中删除设备"""
     # 获取Treeview中所有项的ID
        item_ids = self.tree.get_children()
    
    # 遍历所有项，找到与要删除的设备匹配的项
        for item_id in item_ids:
        # 获取当前项的数据
            item_data = self.tree.item(item_id, 'values')
        
        # 检查IP地址是否匹配
            if item_data[0] == device['ip']:
            # 从Treeview中删除该项
                self.tree.delete(item_id)
            
            # 从devices列表中删除对应的设备
                self.devices.remove(device)
            
            # 记录日志
                self.log(f"已删除设备: {device['ip']}", 'INFO')
            
            # 退出循环，因为我们已经找到了并删除了匹配的项
                break
        else:
        # 如果没有找到匹配的项，则显示警告
            messagebox.showwarning("警告", "未找到要删除的设备")

    def save_config_to_file(self, ip, config):
        """将配置保存到文件"""
        file_path = filedialog.asksaveasfilename(defaultextension=".cfg", filetypes=[("配置文件", "*.cfg")])
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(config)
            self.log(f"{ip} 配置已保存到 {file_path}", 'INFO')
    def _insert_placeholder(self):
        """插入默认文本到命令输入框"""
        self.cmd_text.insert(tk.END, "请输入要执行的命令...\n")
        self.cmd_text.tag_add("placeholder", "1.0", tk.END)
        self.cmd_text.tag_config("placeholder", foreground="gray")

    def _clear_placeholder(self, event):
        """清除命令输入框中的默认文本"""
        if self.cmd_text.tag_ranges("placeholder"):
            self.cmd_text.delete("1.0", tk.END)
            self.cmd_text.tag_remove("placeholder", "1.0", tk.END)
        self.cmd_text.tag_config("placeholder", foreground="black")
        
    def _setup_connection_manager(self):
        """初始化连接管理器"""
        self.conn_manager = HuaweiConnectionManager(self.log_queue)

    def import_devices(self):
        """导入华为设备信息（多线程模式）"""
        file_path = filedialog.askopenfilename(filetypes=[("CSV文件", "*.csv")])
        if not file_path:
            return

        def run_import():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    required_fields = ['ip', 'username', 'password']
                    
                    for row in reader:
                        if not all(field in row for field in required_fields):
                            raise ValueError("CSV文件缺少必要字段")
                        
                        device = {
                            'ip': row['ip'],
                            'username': row['username'],
                            'password': row['password'],
                            'port': int(row.get('port', 22)),
                            'device_type': row.get('device_type', 'huawei')
                        }
                        
                        self.devices.append(device)
                        self.tree.insert("", "end", values=(
                            device['ip'],
                            device['username'],
                            device['port'],
                            device['device_type']
                        ))
                
                self.log(f"成功导入 {len(self.devices)} 台设备", 'INFO')
            except Exception as e:
                self.log(f"导入错误: {str(e)}", 'ERROR')

        threading.Thread(target=run_import, daemon=True).start()

    def clear_devices(self):
        """清空设备列表"""
        self.tree.delete(*self.tree.get_children())
        self.devices = []
        self.log("设备列表已清空", 'INFO')

    def test_connections(self):
        """测试设备连接（多线程模式）"""
        selected_items = self.tree.selection()
        if not selected_items:
            self.log("未选择任何设备", 'WARNING')
            return

        self._toggle_buttons(False)
        self.log("开始连接测试...", 'INFO')

        def run_test():
            for item_id in selected_items:
                tree_data = self.tree.item(item_id, 'values')
                device = next((d for d in self.devices if d['ip'] == tree_data[0]), None)
                if device is None:
                    self.log(f"未找到设备: {tree_data[0]}", 'ERROR')
                    continue
                
                try:
                    success = self.conn_manager.test_connection(device)
                    status = "成功" if success else "失败"
                    self.log(f"{device['ip']} 连接测试{status}", 'INFO' if success else 'ERROR')
                except Exception as e:
                    self.log(f"{device['ip']} 测试异常: {str(e)}", 'ERROR')
            
            self.root.after(0, self._toggle_buttons, True)

        threading.Thread(target=run_test, daemon=True).start()


    def execute_commands(self):
        commands = self.cmd_text.get("1.0", tk.END).strip().splitlines()
        if not commands:
            self.log("请输入要执行的命令", 'WARNING')
            return

        self._toggle_buttons(False)
        self.log(f"开始执行命令: {commands}", 'INFO')

        def run_execute():
            with ThreadPoolExecutor(max_workers=3) as executor:
            # 获取Treeview中当前选中的设备项ID列表
                selected_items = self.tree.selection()
                if not selected_items:
                    self.log("未选择任何设备", 'WARNING')
                    self.root.after(0, self._toggle_buttons, True)
                    return

            # 根据选中项ID获取设备信息，并生成futures列表
                futures = []
                for item_id in selected_items:
                    tree_data = self.tree.item(item_id, 'values')
                    device = next((d for d in self.devices if d['ip'] == tree_data[0]), None)
                    if device:
                        futures.append(executor.submit(self.conn_manager.execute_command, device, commands))

                # 处理futures结果
                for future in as_completed(futures):
                    try:
                        ip, output = future.result()
                        self.log(f"{ip} 执行结果:\n{output}\n", 'INFO')
                    except Exception as e:
                        self.log(f"执行错误: {str(e)}", 'ERROR')

            self.root.after(0, self._toggle_buttons, True)

        threading.Thread(target=run_execute, daemon=True).start()

    def get_configurations(self):
        self._toggle_buttons(False)
        self.log("开始获取设备配置...", 'INFO')

        def run_config():
            with ThreadPoolExecutor(max_workers=3) as executor:
                selected_items = self.tree.selection()
                if not selected_items:
                    self.log("未选择任何设备", 'WARNING')
                    self.root.after(0, self._toggle_buttons, True)
                    return

                futures = []
                for item_id in selected_items:
                    tree_data = self.tree.item(item_id, 'values')
                    device = next((d for d in self.devices if d['ip'] == tree_data[0]), None)
                    if device:
                        futures.append(executor.submit(self.conn_manager.get_configuration, device))

                for future in as_completed(futures):
                    try:
                        ip, config = future.result()
                        self.save_config_to_file(ip, config)
                        self.log(f"{ip} 配置已保存到本地", 'INFO')
                    except Exception as e:
                        self.log(f"配置获取失败: {str(e)}", 'ERROR')

            self.root.after(0, self._toggle_buttons, True)

        threading.Thread(target=run_config, daemon=True).start()

    def save_config_to_file(self, ip, config):
        """将配置保存到文件"""
        file_path = filedialog.asksaveasfilename(defaultextension=".cfg", filetypes=[("配置文件", "*.cfg")])
        if file_path:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(config)

    def _toggle_buttons(self, state):
        for btn in [self.import_btn, self.test_btn, self.run_btn, self.config_btn, self.clear_btn]:
            btn['state'] = 'normal' if state else 'disabled'

    def log(self, message, level='INFO'):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] [{level}] {message}\n"
        self.log_queue.put(log_msg)

    def _update_log(self):
        # 设置批量处理阈值
        batch_size = 10
        start_time = time.time()
    
        while not self.log_queue.empty():
            for _ in range(batch_size):
                if self.log_queue.empty():
                    break
            message = self.log_queue.get()
            self.log_text.config(state='normal')
            self.log_text.insert(tk.END, message)
            self.log_text.see(tk.END)
        
            # 检查是否达到时间阈值
            if time.time() - start_time > 0.1:
                break
    
        self.log_text.config(state='disabled')
        self.root.after(100, self._update_log)

class HuaweiConnectionManager:
    def __init__(self, log_queue):
        self.log_queue = log_queue

    def test_connection(self, device):
        """测试华为设备连接"""
        try:
            conn = self._connect(device)
            if conn:
                conn.disconnect()
                return True
            return False
        except Exception:
            return False

    def execute_command(self, device, commands):
        """执行华为设备命令"""
        output = ""
        try:
            conn = self._connect(device)
            if not conn:
                return (device['ip'], "连接失败")

            # 进入系统视图
            conn.send_command_timing('system-view', strip_prompt=False)
            
            for cmd in commands:
                result = conn.send_command(cmd, delay_factor=2)
                output += f"{cmd}\n{result}\n{'='*40}\n"
            
            return (device['ip'], output)
        except exceptions.NetmikoTimeoutException:
            return (device['ip'], "命令执行超时")
        except exceptions.NetmikoAuthenticationException:
            return (device['ip'], "认证失败")
        except Exception as e:
            return (device['ip'], f"执行错误: {str(e)}")
        finally:
            if 'conn' in locals() and conn:
                conn.disconnect()

    def get_configuration(self, device):
        """获取华为设备配置"""
        try:
            conn = self._connect(device)
            if not conn:
                return (device['ip'], "连接失败")

            # 华为查看配置命令
            config = conn.send_command('display current-configuration')
            return (device['ip'], config)
        except exceptions.ReadTimeout:
            return (device['ip'], "获取配置超时")
        except Exception as e:
            return (device['ip'], f"配置获取错误: {str(e)}")
        finally:
            if 'conn' in locals() and conn:
                conn.disconnect()

    def _connect(self, device):
        """建立华为设备连接"""
        try:
            conn = ConnectHandler(
                device_type=device.get('device_type', 'huawei'),
                host=device['ip'],
                username=device['username'],
                password=device['password'],
                port=device['port'],
                conn_timeout=30,
                auth_timeout=30,
                banner_timeout=30
            )
            # 禁用分页
            conn.send_command('screen-length 0 temporary')
            return conn
        except exceptions.NetmikoTimeoutException as e:
            self.log_queue.put(f"{device['ip']} 连接超时: {str(e)}\n")
        except exceptions.NetmikoAuthenticationException as e:
            self.log_queue.put(f"{device['ip']} 认证失败: {str(e)}\n")
        except Exception as e:
            self.log_queue.put(f"{device['ip']} 连接错误: {str(e)}\n")
        return None

if __name__ == "__main__":
    root = tk.Tk()
    app = HuaweiSwitchManager(root)
    root.mainloop()