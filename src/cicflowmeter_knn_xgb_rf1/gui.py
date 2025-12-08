# nids_gui.py
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import psutil
from collections import deque
from scapy.sendrecv import AsyncSniffer
from cicflowmeter_knn_xgb_rf1.flow_session import FlowSession
from cicflowmeter_knn_xgb_rf1.sniffer import _start_periodic_gc

class NIDSGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("CICFlowMeter - Network Flow Monitor")
        self.root.geometry("700x500")
        self.root.protocol("WM_DELETE_WINDOW", self.exit_app)
        
        self.sniffer = None
        self.session = None
        self.capturing = False
        self.throughput_value = 0
        self.cpu_usage_value = 0
        self.memory_usage_value = 0
        self.packet_count = 0
        self.flow_count = 0
        
        # Performance optimizations
        self.log_queue = deque(maxlen=1000)  # Limit log history
        self.last_update_time = 0
        self.update_interval = 0.1  # 100ms for UI updates
        self.resource_update_interval = 1.0  # 1 second for resource updates
        
        # Default parameters removed: flow_timeout and activity_timeout handled by session defaults
        
        self.setup_gui()
        
    def setup_gui(self):
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title and Control Buttons Frame
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Title
        title_label = ttk.Label(header_frame, text="Network Intrusion Detection System V1.0", 
                               font=("Segoe UI", 14, "bold"))
        title_label.pack(side=tk.LEFT)
        
        # Control Buttons - positioned at top right
        button_frame = ttk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT)
        
        self.start_btn = ttk.Button(
            button_frame,
            text="Start Capture",
            command=self.start_capture,
            width=12
        )
        self.start_btn.pack(side=tk.LEFT, padx=2)

        self.stop_btn = ttk.Button(
            button_frame, 
            text="Stop Capture", 
            command=self.stop_capture,
            state="disabled",
            width=12
        )
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        self.clear_btn = ttk.Button(
            button_frame,
            text="Clear Log",
            command=self.clear_log,
            width=10
        )
        self.clear_btn.pack(side=tk.LEFT, padx=2)

        ttk.Button(
            button_frame, 
            text="Exit", 
            command=self.exit_app,
            width=8
        ).pack(side=tk.LEFT, padx=2)

        # Compact Configuration Frame
        config_frame = ttk.Frame(main_frame)
        config_frame.pack(fill=tk.X, pady=5)
        
        # Network Interface - Compact
        ttk.Label(config_frame, text="Interface:").grid(row=0, column=0, sticky="w", padx=(0, 2))
        self.interface_entry = ttk.Entry(config_frame, width=12)
        self.interface_entry.insert(0, "wlp0s20f3")
        self.interface_entry.grid(row=0, column=1, sticky="w", padx=(0, 10))

        # Model - Compact
        ttk.Label(config_frame, text="Model:").grid(row=0, column=2, sticky="w", padx=(0, 2))
        self.model_entry = ttk.Entry(config_frame, width=40)
        self.model_entry.insert(0, "/home/wahba/Documents/nids5/test/model/binary/knn_binary.joblib")
        self.model_entry.grid(row=0, column=3, sticky="we", padx=(0, 10))
        
        
        # Compact Parameters in same row
        # Flow timeout and inactivity settings removed from GUI
        
        # Reset button
        ttk.Button(
            config_frame, 
            text="Reset", 
            command=self.reset_parameters,
            width=8
        ).grid(row=0, column=10, sticky="e", padx=(0, 5))
        
        config_frame.columnconfigure(3, weight=1)
        config_frame.columnconfigure(10, weight=1)

        # System Metrics - More compact
        metrics_frame = ttk.Frame(main_frame)
        metrics_frame.pack(fill=tk.X, pady=3)
        
        # Create metrics in a single row with smaller spacing
        self.cpu_label = ttk.Label(metrics_frame, text="CPU: --%", font=("Consolas", 9))
        self.cpu_label.pack(side=tk.LEFT, padx=8)
        
        self.mem_label = ttk.Label(metrics_frame, text="Memory: --%", font=("Consolas", 9))
        self.mem_label.pack(side=tk.LEFT, padx=8)
        
        self.power_label = ttk.Label(metrics_frame, text="Power: --", font=("Consolas", 9))
        self.power_label.pack(side=tk.LEFT, padx=8)
        
        self.throughput_label = ttk.Label(metrics_frame, text="Throughput: -- pkt/s", font=("Consolas", 9))
        self.throughput_label.pack(side=tk.LEFT, padx=8)

        self.packet_count_label = ttk.Label(metrics_frame, text="Packet Count: --", font=("Consolas", 9))
        self.packet_count_label.pack(side=tk.LEFT, padx=8)

        # Status bar for parameter descr/home/wahba/Documents/nids3/src/nids_gui3.pyiptions
        self.status_bar = ttk.Label(main_frame, text="Timeout: Flow expiration | Feature: Extraction interval", 
                       font=("Consolas", 8), foreground="gray")
        self.status_bar.pack(fill=tk.X, pady=(0, 5))

        # Log widget with optimized configuration - now gets more space
        log_frame = ttk.LabelFrame(main_frame, text="Detection Log", padding="3")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_widget = scrolledtext.ScrolledText(
            log_frame, 
            bg="black", 
            fg="lime", 
            insertbackground="white",
            font=("Consolas", 9),
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_widget.pack(fill=tk.BOTH, expand=True)

        # Quick Access Buttons at bottom
        quick_button_frame = ttk.Frame(main_frame)
        quick_button_frame.pack(fill=tk.X, pady=3)
        
        ttk.Button(
            quick_button_frame,
            text="Clear Log",
            command=self.clear_log,
            width=10
        ).pack(side=tk.RIGHT, padx=2)
        
        ttk.Button(
            quick_button_frame,
            text="Copy Log",
            command=self.copy_log,
            width=10
        ).pack(side=tk.RIGHT, padx=2)
        
        # Add a save log button
        ttk.Button(
            quick_button_frame,
            text="Save Log",
            command=self.save_log,
            width=10
        ).pack(side=tk.RIGHT, padx=2)

    def reset_parameters(self):
        """Reset parameters to default values"""
        # Flow timeout/activity timeout removed from GUI; session defaults remain in effect
        self._update_log_widget("[*] Parameters reset to defaults (no GUI timeouts)\n")

    def copy_log(self):
        """Copy log contents to clipboard"""
        try:
            log_content = self.log_widget.get(1.0, tk.END)
            if log_content.strip():
                self.root.clipboard_clear()
                self.root.clipboard_append(log_content)
                self._update_log_widget("[*] Log copied to clipboard\n")
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to copy log: {str(e)}\n")

    def save_log(self):
        """Save log contents to file"""
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
            if filename:
                log_content = self.log_widget.get(1.0, tk.END)
                with open(filename, 'w') as f:
                    f.write(log_content)
                self._update_log_widget(f"[*] Log saved to {filename}\n")
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to save log: {str(e)}\n")

    def validate_parameters(self):
        """Validate all parameters before starting capture"""
        try:
            # No GUI timeouts to validate; rely on session defaults or configuration
            return True
            
        except tk.TclError:
            self._update_log_widget("[ERROR] Invalid parameter values\n")
            return False

    def _process_log_queue(self):
        """Process accumulated log entries in batch"""
        if not self.log_queue:
            return
            
        self.log_widget.config(state=tk.NORMAL)
        
        # Batch insert to reduce GUI updates
        batch_size = min(50, len(self.log_queue))  # Process up to 50 entries at once
        batch_text = ''.join([self.log_queue.popleft() for _ in range(batch_size)])
        
        self.log_widget.insert(tk.END, batch_text)
        self.log_widget.see(tk.END)
        self.log_widget.config(state=tk.DISABLED)
        
        # If there are more entries, schedule another update
        if self.log_queue:
            self.root.after(10, self._process_log_queue)

    def start_capture(self):
        """Start packet capture"""
        if self.capturing:
            return
            
        interface = self.interface_entry.get().strip()
        model_path1 = self.model_entry.get().strip()
        
        if not interface:
            self._update_log_widget("[ERROR] Please specify a network interface\n")
            return
            
        # Validate parameters
        if not self.validate_parameters():
            return
            
        # Disable UI during startup
        self._set_ui_state(False)
            
        try:
            self.session = FlowSession(
                output_mode="csv",
                model_path1=model_path1,
                update_log_widget=self._update_log_widget,
                verbose=True,
            )
            
            # Start periodic garbage collection (from sniffer.py)
            _start_periodic_gc(self.session, interval=1.0)
            
            # Create AsyncSniffer
            self.sniffer = AsyncSniffer(
                iface=interface,
                filter="ip and (tcp or udp)",
                prn=self.session.process,
                store=False,
            )
            
            # Start sniffer in background
            self.sniffer.start()
            self.capturing = True
            
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
            
            self._update_log_widget(f"[*] Started packet capture on interface {interface}\n")
            self._update_log_widget(f"[*] Model path: {self.model_entry.get().strip()}\n")
            self._update_log_widget("[*] Using session default timeouts\n")
            
            # Start monitoring thread
            threading.Thread(target=self._monitor_capture, daemon=True).start()
            
        except FileNotFoundError as e:
            self._update_log_widget(f"[ERROR] File not found: {str(e)}\n")
            self._set_ui_state(True)
        except PermissionError:
            self._update_log_widget(f"[ERROR] Permission denied. Try running with sudo.\n")
            self._set_ui_state(True)
        except Exception as e:
            self._update_log_widget(f"[ERROR] Failed to start capture: {str(e)}\n")
            self._set_ui_state(True)

    def _monitor_capture(self):
        """Monitor packet capture and update statistics"""
        last_packet_count = 0
        last_time = time.time()
        
        while self.capturing:
            try:
                current_time = time.time()
                elapsed = current_time - last_time
                
                if self.session and elapsed >= 1.0:  # Update every second
                    # Get current packet count
                    current_packet_count = self.session.packets_count
                    
                    # Calculate throughput
                    packets_diff = current_packet_count - last_packet_count
                    self.throughput_value = int(packets_diff / elapsed)
                    
                    # Update flow count
                    with self.session._lock:
                        self.flow_count = len(self.session.flows)
                    
                    # Log status periodically
                    # if current_packet_count % 1000 == 0 and current_packet_count > 0:
                    #     log_entry = f"[*] Processed {current_packet_count} packets, {self.flow_count} active flows\n"
                    #     self.log_queue.append(log_entry)
                    
                    # Update for next iteration
                    last_packet_count = current_packet_count
                    last_time = current_time
                    
                    # Update resource usage
                    process = psutil.Process()
                    self.cpu_usage_value = process.cpu_percent(interval=0.1)
                    self.memory_usage_value = process.memory_info().rss / 1024 / 1024  # MB
                
                time.sleep(0.5)
                
            except Exception as e:
                print(f"Error in monitor: {e}")
                break

    def _set_ui_state(self, enabled):
        """Enable/disable UI elements"""
        state = "normal" if enabled else "disabled"
        self.start_btn.config(state=state)
        self.interface_entry.config(state=state)
        self.model_entry.config(state=state)

    def stop_capture(self):
        """Stop packet capture"""
        if self.sniffer and self.capturing:
            self.capturing = False
            
            try:
                self.sniffer.stop()
                
                # Stop periodic GC (from sniffer.py)
                if self.session and hasattr(self.session, "_gc_stop"):
                    self.session._gc_stop.set()
                    if hasattr(self.session, "_gc_thread"):
                        self.session._gc_thread.join(timeout=2.0)
                
                # Flush remaining flows
                if self.session:
                    self.session.flush_flows()
                    self._update_log_widget(f"[*] Final stats: {self.session.packets_count} packets, {self.flow_count} flows\n")
                
            except Exception as e:
                self._update_log_widget(f"[ERROR] Error stopping capture: {str(e)}\n")
            
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self._set_ui_state(True)
            
            self._update_log_widget("[!] Stopped packet capture\n")

    def _update_log_widget(self, message):
        """Immediate log update for important messages"""
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.insert(tk.END, message)
        self.log_widget.see(tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def clear_log(self):
        """Clear the log widget and queue"""
        self.log_queue.clear()
        self.log_widget.config(state=tk.NORMAL)
        self.log_widget.delete(1.0, tk.END)
        self.log_widget.config(state=tk.DISABLED)

    def update_system_metrics(self):
        """Update system resource usage displays"""
        try:
            # Get battery info if available
            battery = psutil.sensors_battery() if hasattr(psutil, "sensors_battery") else None
            power_status = "Plugged" if battery and battery.power_plugged else "Battery" if battery else "Unknown"
            
            # Update labels
            throughput_text = f"Throughput: {self.throughput_value} pkt/s"
            cpu_text = f"CPU: {self.cpu_usage_value:.1f}%"
            mem_text = f"Memory: {self.memory_usage_value:.1f} MB"
            power_text = f"Power: {power_status}"
            packet_count_text = f"Packet Count: {self.session.packets_count if self.session else 0}"
            
            self.cpu_label.config(text=cpu_text)
            self.mem_label.config(text=mem_text)
            self.power_label.config(text=power_text)
            self.throughput_label.config(text=throughput_text)
            self.packet_count_label.config(text=packet_count_text)
            
        except Exception as e:
            print(f"Error updating system metrics: {e}")

    def exit_app(self):
        """Clean exit from application"""
        if self.capturing and self.sniffer:
            self.stop_capture()
        
        if self.root:
            self.root.quit()
            self.root.destroy()

    def run(self):
        """Start the GUI application"""
        # Start periodic updates for system metrics
        def periodic_updates():
            while True:
                try:
                    if not self.root.winfo_exists():
                        break
                    
                    # Update system metrics
                    self.root.after(0, self.update_system_metrics)
                    
                    # Process any remaining log entries
                    if self.log_queue:
                        self.root.after(0, self._process_log_queue)
                    
                    time.sleep(self.resource_update_interval)
                    
                except Exception as e:
                    print(f"Error in periodic updates: {e}")
                    break
        
        # Start background thread for updates
        threading.Thread(target=periodic_updates, daemon=True).start()
        
        # Start the GUI main loop
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.exit_app()


if __name__ == "__main__":
    app = NIDSGUI()
    app.run()