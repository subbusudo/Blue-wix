#!/usr/bin/env python3
"""
PyQt5 GUI for the Intrusion Detection System.
Follows single main UI thread pattern with worker threads for heavy operations.
"""

import sys
import json
import threading
import time
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QGridLayout, QLabel, QPushButton, 
                             QTextEdit, QTableWidget, QTableWidgetItem, QTabWidget,
                             QGroupBox, QLineEdit, QSpinBox, QCheckBox, QComboBox,
                             QProgressBar, QStatusBar, QMessageBox, QSplitter,
                             QHeaderView, QFrame)
from PyQt5.QtCore import QTimer, QThread, pyqtSignal, Qt, QMutex, QMutexLocker
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
from ids_core import IDSCore


class IDSWorkerThread(QThread):
    """Worker thread for IDS operations to keep UI responsive."""
    
    alert_received = pyqtSignal(dict)
    stats_updated = pyqtSignal(dict)
    status_changed = pyqtSignal(str)
    
    def __init__(self, ids_core):
        super().__init__()
        self.ids_core = ids_core
        self.running = False
        self.mutex = QMutex()
        
    def run(self):
        """Main worker thread loop."""
        self.running = True
        self.status_changed.emit("Starting IDS...")
        
        # Set up alert callback
        self.ids_core.set_alert_callback(self.handle_alert)
        
        # Start monitoring
        if self.ids_core.start_monitoring():
            self.status_changed.emit("IDS Running")
            
            # Update statistics periodically
            while self.running:
                with QMutexLocker(self.mutex):
                    if self.running:
                        stats = self.ids_core.get_statistics()
                        self.stats_updated.emit(stats)
                self.msleep(1000)  # Update every second
        else:
            self.status_changed.emit("Failed to start IDS")
    
    def handle_alert(self, alert):
        """Handle alerts from IDS core."""
        self.alert_received.emit(alert)
    
    def stop(self):
        """Stop the worker thread."""
        with QMutexLocker(self.mutex):
            self.running = False
        self.ids_core.stop_monitoring()
        self.status_changed.emit("IDS Stopped")
        self.wait()


class AlertTableWidget(QTableWidget):
    """Custom table widget for displaying alerts."""
    
    def __init__(self):
        super().__init__()
        self.setup_table()
        
    def setup_table(self):
        """Setup the alert table."""
        headers = ['Time', 'Type', 'Severity', 'Source', 'Description']
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        
        # Configure table appearance
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        
        # Set row height
        self.verticalHeader().setDefaultSectionSize(25)
        
    def add_alert(self, alert):
        """Add a new alert to the table."""
        row_position = self.rowCount()
        self.insertRow(row_position)
        
        # Color coding based on severity
        severity_colors = {
            'LOW': QColor(255, 255, 0),      # Yellow
            'MEDIUM': QColor(255, 165, 0),   # Orange
            'HIGH': QColor(255, 0, 0),       # Red
            'CRITICAL': QColor(128, 0, 128)  # Purple
        }
        
        # Add items
        items = [
            alert.get('timestamp', datetime.now()).strftime('%H:%M:%S'),
            alert.get('type', 'UNKNOWN'),
            alert.get('severity', 'UNKNOWN'),
            alert.get('source', 'Unknown'),
            alert.get('description', 'No description')
        ]
        
        for col, item_text in enumerate(items):
            item = QTableWidgetItem(str(item_text))
            
            # Color code severity
            if col == 2 and item_text in severity_colors:
                item.setBackground(severity_colors[item_text])
                item.setForeground(QColor(0, 0, 0))  # Black text
            
            self.setItem(row_position, col, item)
        
        # Scroll to bottom
        self.scrollToBottom()
        
        # Limit to 1000 rows to prevent memory issues
        if self.rowCount() > 1000:
            self.removeRow(0)


class StatisticsWidget(QWidget):
    """Widget for displaying IDS statistics."""
    
    def __init__(self):
        super().__init__()
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the statistics UI."""
        layout = QVBoxLayout()
        
        # Create statistics labels
        self.stats_labels = {}
        stats_info = [
            ('uptime', 'Uptime'),
            ('packets_analyzed', 'Packets Analyzed'),
            ('alerts_generated', 'Alerts Generated'),
            ('running', 'Status')
        ]
        
        for key, label in stats_info:
            group = QGroupBox(label)
            group_layout = QHBoxLayout()
            
            value_label = QLabel('0')
            value_label.setFont(QFont('Arial', 12, QFont.Bold))
            value_label.setStyleSheet("color: #2E8B57;")
            
            group_layout.addWidget(value_label)
            group.setLayout(group_layout)
            
            self.stats_labels[key] = value_label
            layout.addWidget(group)
        
        # Attack types section
        attack_group = QGroupBox("Attack Types Detected")
        attack_layout = QVBoxLayout()
        
        self.attack_labels = {}
        attack_types = ['PORT_SCAN', 'SYN_FLOOD', 'SUSPICIOUS_PORT', 'LARGE_PACKET', 'SIZE_ANOMALY']
        
        for attack_type in attack_types:
            label = QLabel(f"{attack_type}: 0")
            label.setStyleSheet("color: #DC143C;")
            self.attack_labels[attack_type] = label
            attack_layout.addWidget(label)
        
        attack_group.setLayout(attack_layout)
        layout.addWidget(attack_group)
        
        # Top sources/destinations
        sources_group = QGroupBox("Top Sources")
        sources_layout = QVBoxLayout()
        self.sources_text = QTextEdit()
        self.sources_text.setMaximumHeight(100)
        self.sources_text.setReadOnly(True)
        sources_layout.addWidget(self.sources_text)
        sources_group.setLayout(sources_layout)
        layout.addWidget(sources_group)
        
        destinations_group = QGroupBox("Top Destinations")
        destinations_layout = QVBoxLayout()
        self.destinations_text = QTextEdit()
        self.destinations_text.setMaximumHeight(100)
        self.destinations_text.setReadOnly(True)
        destinations_layout.addWidget(self.destinations_text)
        destinations_group.setLayout(destinations_layout)
        layout.addWidget(destinations_group)
        
        self.setLayout(layout)
    
    def update_statistics(self, stats):
        """Update statistics display."""
        # Update basic stats
        self.stats_labels['uptime'].setText(stats.get('uptime', '0:00:00'))
        self.stats_labels['packets_analyzed'].setText(str(stats.get('packets_analyzed', 0)))
        self.stats_labels['alerts_generated'].setText(str(stats.get('alerts_generated', 0)))
        
        status = "Running" if stats.get('running', False) else "Stopped"
        color = "#2E8B57" if stats.get('running', False) else "#DC143C"
        self.stats_labels['running'].setText(status)
        self.stats_labels['running'].setStyleSheet(f"color: {color};")
        
        # Update attack types
        attacks = stats.get('attacks_detected', {})
        for attack_type, label in self.attack_labels.items():
            count = attacks.get(attack_type, 0)
            label.setText(f"{attack_type}: {count}")
        
        # Update top sources
        sources = stats.get('top_sources', {})
        sources_text = "\n".join([f"{ip}: {count}" for ip, count in list(sources.items())[:5]])
        self.sources_text.setPlainText(sources_text)
        
        # Update top destinations
        destinations = stats.get('top_destinations', {})
        destinations_text = "\n".join([f"{ip}: {count}" for ip, count in list(destinations.items())[:5]])
        self.destinations_text.setPlainText(destinations_text)


class ConfigurationWidget(QWidget):
    """Widget for IDS configuration."""
    
    def __init__(self, ids_core):
        super().__init__()
        self.ids_core = ids_core
        self.setup_ui()
        self.load_config()
        
    def setup_ui(self):
        """Setup the configuration UI."""
        layout = QVBoxLayout()
        
        # Interface selection
        interface_group = QGroupBox("Network Interface")
        interface_layout = QHBoxLayout()
        
        interface_layout.addWidget(QLabel("Interface:"))
        self.interface_combo = QComboBox()
        self.interface_combo.addItems(["any", "eth0", "wlan0", "lo"])
        interface_layout.addWidget(self.interface_combo)
        
        interface_group.setLayout(interface_layout)
        layout.addWidget(interface_group)
        
        # Signature rules
        rules_group = QGroupBox("Signature Detection Rules")
        rules_layout = QGridLayout()
        
        rules_layout.addWidget(QLabel("Port Scan Threshold:"), 0, 0)
        self.port_scan_spin = QSpinBox()
        self.port_scan_spin.setRange(1, 100)
        self.port_scan_spin.setValue(10)
        rules_layout.addWidget(self.port_scan_spin, 0, 1)
        
        rules_layout.addWidget(QLabel("SYN Flood Threshold:"), 1, 0)
        self.syn_flood_spin = QSpinBox()
        self.syn_flood_spin.setRange(1, 1000)
        self.syn_flood_spin.setValue(50)
        rules_layout.addWidget(self.syn_flood_spin, 1, 1)
        
        rules_layout.addWidget(QLabel("Large Packet Threshold:"), 2, 0)
        self.large_packet_spin = QSpinBox()
        self.large_packet_spin.setRange(100, 10000)
        self.large_packet_spin.setValue(1500)
        rules_layout.addWidget(self.large_packet_spin, 2, 1)
        
        rules_group.setLayout(rules_layout)
        layout.addWidget(rules_group)
        
        # Anomaly detection
        anomaly_group = QGroupBox("Anomaly Detection")
        anomaly_layout = QVBoxLayout()
        
        self.anomaly_enabled = QCheckBox("Enable Anomaly Detection")
        self.anomaly_enabled.setChecked(True)
        anomaly_layout.addWidget(self.anomaly_enabled)
        
        anomaly_sub_layout = QGridLayout()
        anomaly_sub_layout.addWidget(QLabel("Connection Rate Threshold:"), 0, 0)
        self.connection_rate_spin = QSpinBox()
        self.connection_rate_spin.setRange(1, 1000)
        self.connection_rate_spin.setValue(20)
        anomaly_sub_layout.addWidget(self.connection_rate_spin, 0, 1)
        
        anomaly_sub_layout.addWidget(QLabel("Packet Size Deviation:"), 1, 0)
        self.packet_deviation_spin = QSpinBox()
        self.packet_deviation_spin.setRange(1, 10)
        self.packet_deviation_spin.setValue(2)
        anomaly_sub_layout.addWidget(self.packet_deviation_spin, 1, 1)
        
        anomaly_layout.addLayout(anomaly_sub_layout)
        anomaly_group.setLayout(anomaly_layout)
        layout.addWidget(anomaly_group)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.save_button = QPushButton("Save Configuration")
        self.save_button.clicked.connect(self.save_config)
        button_layout.addWidget(self.save_button)
        
        self.reset_button = QPushButton("Reset to Defaults")
        self.reset_button.clicked.connect(self.reset_config)
        button_layout.addWidget(self.reset_button)
        
        layout.addLayout(button_layout)
        layout.addStretch()
        
        self.setLayout(layout)
    
    def load_config(self):
        """Load current configuration."""
        config = self.ids_core.config
        
        # Interface
        interface = config.get('interface', 'any')
        index = self.interface_combo.findText(interface)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)
        
        # Signature rules
        rules = config.get('signature_rules', {})
        self.port_scan_spin.setValue(rules.get('port_scan_threshold', 10))
        self.syn_flood_spin.setValue(rules.get('syn_flood_threshold', 50))
        self.large_packet_spin.setValue(rules.get('large_packet_threshold', 1500))
        
        # Anomaly detection
        anomaly = config.get('anomaly_detection', {})
        self.anomaly_enabled.setChecked(anomaly.get('enabled', True))
        self.connection_rate_spin.setValue(anomaly.get('connection_rate_threshold', 20))
        self.packet_deviation_spin.setValue(anomaly.get('packet_size_deviation', 2.0))
    
    def save_config(self):
        """Save configuration."""
        config = self.ids_core.config
        
        # Update configuration
        config['interface'] = self.interface_combo.currentText()
        
        config['signature_rules'].update({
            'port_scan_threshold': self.port_scan_spin.value(),
            'syn_flood_threshold': self.syn_flood_spin.value(),
            'large_packet_threshold': self.large_packet_spin.value()
        })
        
        config['anomaly_detection'].update({
            'enabled': self.anomaly_enabled.isChecked(),
            'connection_rate_threshold': self.connection_rate_spin.value(),
            'packet_size_deviation': self.packet_deviation_spin.value()
        })
        
        # Save to file
        try:
            with open('ids_config.json', 'w') as f:
                json.dump(config, f, indent=4)
            
            QMessageBox.information(self, "Success", "Configuration saved successfully!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save configuration: {e}")
    
    def reset_config(self):
        """Reset configuration to defaults."""
        reply = QMessageBox.question(self, "Reset Configuration", 
                                   "Are you sure you want to reset to default configuration?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            self.ids_core.config = self.ids_core.load_config("ids_config.json")
            self.load_config()


class IDSMainWindow(QMainWindow):
    """Main window for the IDS application."""
    
    def __init__(self):
        super().__init__()
        self.ids_core = IDSCore()
        self.worker_thread = None
        self.setup_ui()
        self.setup_timers()
        
    def setup_ui(self):
        """Setup the main UI."""
        self.setWindowTitle("Intrusion Detection System (IDS)")
        self.setGeometry(100, 100, 1200, 800)
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout()
        
        # Create control panel
        control_panel = self.create_control_panel()
        main_layout.addWidget(control_panel)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        
        # Alerts tab
        alerts_tab = QWidget()
        alerts_layout = QVBoxLayout()
        
        self.alert_table = AlertTableWidget()
        alerts_layout.addWidget(self.alert_table)
        
        # Alert controls
        alert_controls = QHBoxLayout()
        self.clear_alerts_button = QPushButton("Clear Alerts")
        self.clear_alerts_button.clicked.connect(self.clear_alerts)
        alert_controls.addWidget(self.clear_alerts_button)
        alert_controls.addStretch()
        
        alerts_layout.addLayout(alert_controls)
        alerts_tab.setLayout(alerts_layout)
        self.tab_widget.addTab(alerts_tab, "Alerts")
        
        # Statistics tab
        self.stats_widget = StatisticsWidget()
        self.tab_widget.addTab(self.stats_widget, "Statistics")
        
        # Configuration tab
        self.config_widget = ConfigurationWidget(self.ids_core)
        self.tab_widget.addTab(self.config_widget, "Configuration")
        
        main_layout.addWidget(self.tab_widget)
        
        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("IDS Ready")
        
        central_widget.setLayout(main_layout)
        
        # Apply dark theme
        self.apply_dark_theme()
    
    def create_control_panel(self):
        """Create the control panel."""
        panel = QFrame()
        panel.setFrameStyle(QFrame.StyledPanel)
        panel.setMaximumHeight(80)
        
        layout = QHBoxLayout()
        
        # Start/Stop buttons
        self.start_button = QPushButton("Start IDS")
        self.start_button.clicked.connect(self.start_ids)
        self.start_button.setStyleSheet("QPushButton { background-color: #2E8B57; color: white; font-weight: bold; }")
        
        self.stop_button = QPushButton("Stop IDS")
        self.stop_button.clicked.connect(self.stop_ids)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("QPushButton { background-color: #DC143C; color: white; font-weight: bold; }")
        
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        
        # Status indicator
        layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Stopped")
        self.status_label.setStyleSheet("color: #DC143C; font-weight: bold;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        
        # Packet counter
        layout.addWidget(QLabel("Packets:"))
        self.packet_label = QLabel("0")
        self.packet_label.setStyleSheet("color: #2E8B57; font-weight: bold;")
        layout.addWidget(self.packet_label)
        
        # Alert counter
        layout.addWidget(QLabel("Alerts:"))
        self.alert_label = QLabel("0")
        self.alert_label.setStyleSheet("color: #DC143C; font-weight: bold;")
        layout.addWidget(self.alert_label)
        
        panel.setLayout(layout)
        return panel
    
    def setup_timers(self):
        """Setup UI update timers."""
        # Timer for updating packet/alert counters
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_counters)
        self.update_timer.start(1000)  # Update every second
    
    def apply_dark_theme(self):
        """Apply a dark theme to the application."""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
        dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
        
        self.setPalette(dark_palette)
    
    def start_ids(self):
        """Start the IDS."""
        if self.worker_thread and self.worker_thread.isRunning():
            return
        
        # Create and start worker thread
        self.worker_thread = IDSWorkerThread(self.ids_core)
        self.worker_thread.alert_received.connect(self.handle_alert)
        self.worker_thread.stats_updated.connect(self.update_statistics)
        self.worker_thread.status_changed.connect(self.update_status)
        self.worker_thread.start()
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_bar.showMessage("Starting IDS...")
    
    def stop_ids(self):
        """Stop the IDS."""
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.stop()
            self.worker_thread = None
        
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("IDS Stopped")
    
    def handle_alert(self, alert):
        """Handle incoming alerts."""
        self.alert_table.add_alert(alert)
        
        # Update alert counter
        self.alert_label.setText(str(self.ids_core.alert_count))
        
        # Show critical alerts in status bar
        if alert.get('severity') == 'HIGH':
            self.status_bar.showMessage(f"HIGH SEVERITY ALERT: {alert.get('description', 'Unknown')}", 5000)
    
    def update_statistics(self, stats):
        """Update statistics display."""
        self.stats_widget.update_statistics(stats)
    
    def update_status(self, status):
        """Update status display."""
        self.status_label.setText(status)
        if status == "IDS Running":
            self.status_label.setStyleSheet("color: #2E8B57; font-weight: bold;")
        else:
            self.status_label.setStyleSheet("color: #DC143C; font-weight: bold;")
    
    def update_counters(self):
        """Update packet and alert counters."""
        if self.ids_core.running:
            self.packet_label.setText(str(self.ids_core.packet_count))
            self.alert_label.setText(str(self.ids_core.alert_count))
    
    def clear_alerts(self):
        """Clear all alerts from the table."""
        self.alert_table.setRowCount(0)
    
    def closeEvent(self, event):
        """Handle application close event."""
        if self.worker_thread and self.worker_thread.isRunning():
            self.stop_ids()
        event.accept()


def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    app.setApplicationName("IDS")
    app.setApplicationVersion("1.0")
    
    # Check for root privileges (required for packet capture)
    import os
    if os.geteuid() != 0:
        QMessageBox.warning(None, "Permission Required", 
                          "This application requires root privileges to capture network packets.\n"
                          "Please run with sudo or as root.")
        sys.exit(1)
    
    window = IDSMainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
