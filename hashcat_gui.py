#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import subprocess
import threading
import os

class HashcatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hashcat GUI")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # 设置主题
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # 变量
        self.hash_type = tk.StringVar(value="0")  # MD5默认
        self.attack_mode = tk.StringVar(value="0")  # 字典攻击默认
        self.input_file = tk.StringVar()
        self.dict_file = tk.StringVar()
        self.mask = tk.StringVar(value="?a?a?a?a?a?a?a?a")
        self.custom_wordlist = tk.StringVar()
        self.output_text = tk.StringVar()
        
        # 高级选项
        self.show = tk.BooleanVar(value=True)
        self.potfile = tk.BooleanVar(value=True)
        self.restore = tk.BooleanVar(value=True)
        self.force = tk.BooleanVar(value=False)
        self.workload_profile = tk.StringVar(value="2")
        
        # 创建主框架
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # 创建左侧配置面板
        self.config_frame = ttk.LabelFrame(self.main_frame, text="配置选项", padding="10")
        self.config_frame.pack(side=tk.LEFT, fill=tk.Y, expand=False, padx=(0, 10))
        
        # 创建右侧输出面板
        self.output_frame = ttk.LabelFrame(self.main_frame, text="输出结果", padding="10")
        self.output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # 构建配置面板
        self.build_config_panel()
        
        # 构建输出面板
        self.build_output_panel()
        
        # 运行状态
        self.running = False
        self.process = None
    
    def build_config_panel(self):
        # 哈希类型选择
        hash_type_label = ttk.Label(self.config_frame, text="哈希类型:")
        hash_type_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.hash_type_combo = ttk.Combobox(self.config_frame, textvariable=self.hash_type, width=40)
        self.hash_type_combo['values'] = [
            "0 - MD5",
            "100 - SHA1",
            "1400 - SHA2-256",
            "1700 - SHA2-512",
            "2500 - WPA/WPA2",
            "3000 - LM",
            "5500 - NetNTLMv1",
            "5600 - NetNTLMv2",
            "1000 - NTLM",
            "1300 - Kerberos 5 TGS-REP",
            "1500 - descrypt",
            "7400 - SHA2-256crypt",
            "7900 - SHA2-512crypt"
        ]
        self.hash_type_combo.pack(anchor=tk.W, pady=(0, 10))
        
        # 攻击模式选择
        attack_mode_label = ttk.Label(self.config_frame, text="攻击模式:")
        attack_mode_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.attack_mode_combo = ttk.Combobox(self.config_frame, textvariable=self.attack_mode, width=40)
        self.attack_mode_combo['values'] = [
            "0 - 字典攻击",
            "1 - 组合攻击",
            "3 - 掩码攻击",
            "6 - 混合字典+掩码攻击",
            "7 - 混合掩码+字典攻击",
            "9 - 关联攻击"
        ]
        self.attack_mode_combo.pack(anchor=tk.W, pady=(0, 10))
        
        # 输入文件选择
        input_label = ttk.Label(self.config_frame, text="哈希文件:")
        input_label.pack(anchor=tk.W, pady=(0, 5))
        
        input_frame = ttk.Frame(self.config_frame)
        input_frame.pack(anchor=tk.W, fill=tk.X, pady=(0, 10))
        
        self.input_entry = ttk.Entry(input_frame, textvariable=self.input_file, width=30)
        self.input_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.input_button = ttk.Button(input_frame, text="浏览", command=self.browse_input_file)
        self.input_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        # 字典文件选择
        dict_label = ttk.Label(self.config_frame, text="字典文件:")
        dict_label.pack(anchor=tk.W, pady=(0, 5))
        
        dict_frame = ttk.Frame(self.config_frame)
        dict_frame.pack(anchor=tk.W, fill=tk.X, pady=(0, 10))
        
        self.dict_entry = ttk.Entry(dict_frame, textvariable=self.dict_file, width=30)
        self.dict_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.dict_button = ttk.Button(dict_frame, text="浏览", command=self.browse_dict_file)
        self.dict_button.pack(side=tk.RIGHT, padx=(5, 0))
        
        # 掩码输入
        mask_label = ttk.Label(self.config_frame, text="掩码 (掩码攻击):")
        mask_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.mask_entry = ttk.Entry(self.config_frame, textvariable=self.mask, width=40)
        self.mask_entry.pack(anchor=tk.W, pady=(0, 10))
        
        # 运行按钮
        self.run_button = ttk.Button(self.config_frame, text="开始攻击", command=self.run_hashcat, style="Accent.TButton")
        self.run_button.pack(anchor=tk.CENTER, pady=10)
        
        self.stop_button = ttk.Button(self.config_frame, text="停止攻击", command=self.stop_hashcat, state=tk.DISABLED)
        self.stop_button.pack(anchor=tk.CENTER, pady=10)
    
    def build_output_panel(self):
        # 创建输出文本框
        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD, width=60, height=25)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        
        # 创建命令显示标签
        self.command_label = ttk.Label(self.output_frame, text="执行命令:")
        self.command_label.pack(anchor=tk.W, pady=(10, 5))
        
        self.command_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD, width=60, height=3)
        self.command_text.pack(fill=tk.X, expand=False)
    
    def browse_input_file(self):
        file_path = filedialog.askopenfilename(
            title="选择哈希文件",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.input_file.set(file_path)
    
    def browse_dict_file(self):
        file_path = filedialog.askopenfilename(
            title="选择字典文件",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            self.dict_file.set(file_path)
    
    def build_command(self):
        # 构建hashcat命令
        command = ["hashcat.exe"]
        
        # 添加哈希类型
        hash_type = self.hash_type.get().split()[0]
        command.extend(["-m", hash_type])
        
        # 添加攻击模式
        attack_mode = self.attack_mode.get().split()[0]
        command.extend(["-a", attack_mode])
        
        # 添加输入文件
        if self.input_file.get():
            command.append(self.input_file.get())
        else:
            messagebox.showerror("错误", "请选择哈希文件")
            return None
        
        # 根据攻击模式添加字典或掩码
        if attack_mode == "0" or attack_mode == "1" or attack_mode == "6" or attack_mode == "7" or attack_mode == "9":
            if self.dict_file.get():
                command.append(self.dict_file.get())
            else:
                messagebox.showerror("错误", "请选择字典文件")
                return None
        
        if attack_mode == "3" or attack_mode == "6" or attack_mode == "7":
            if self.mask.get():
                command.append(self.mask.get())
        
        return command
    
    def run_hashcat(self):
        if self.running:
            return
        
        command = self.build_command()
        if not command:
            return
        
        # 显示命令
        self.command_text.delete(1.0, tk.END)
        self.command_text.insert(tk.END, " ".join(command))
        
        # 清空输出
        self.output_text.delete(1.0, tk.END)
        
        # 更新按钮状态
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.running = True
        
        # 在新线程中运行hashcat
        threading.Thread(target=self.execute_hashcat, args=(command,), daemon=True).start()
    
    def execute_hashcat(self, command):
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in iter(self.process.stdout.readline, ''):
                if not self.running:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
            
            self.process.wait()
        except Exception as e:
            self.output_text.insert(tk.END, f"执行错误: {str(e)}\n")
            self.output_text.see(tk.END)
        finally:
            self.running = False
            self.process = None
            # 恢复按钮状态
            self.root.after(0, lambda: self.run_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_button.config(state=tk.DISABLED))
    
    def stop_hashcat(self):
        if self.running and self.process:
            self.running = False
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.output_text.insert(tk.END, "\n攻击已停止\n")
            self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = HashcatGUI(root)
    root.mainloop()