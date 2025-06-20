import sys
import json
import socket
from datetime import datetime
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QRadioButton, QButtonGroup, QLineEdit, QTextEdit, QPushButton, QLabel, QGroupBox, QMessageBox)
from PySide6.QtCore import QThread, Signal
from PySide6.QtGui import QFont


class NetworkThread(QThread):
    message_received = Signal(str)
    status_changed = Signal(str)
    
    def __init__(self, mode, protocol, host, port, message=""):
        super().__init__()
        self.mode = mode  # "send" or "receive"
        self.protocol = protocol  # "tcp" or "udp"
        self.host = host
        self.port = port
        self.message = message
        self.running = False
        self.socket = None
        
    def run(self):
        self.running = True
        try:
            if self.mode == "send":
                self.send_data()
            else:
                self.receive_data()
        except Exception as e:
            self.status_changed.emit(f"오류: {str(e)}")
            
    def send_data(self):
        try:
            if self.protocol == "tcp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.host, self.port))
                self.socket.send(self.message.encode('utf-8'))
                self.status_changed.emit(f"TCP 메시지 전송 완료: {self.host}:{self.port}")
                
                # 응답 대기
                response = self.socket.recv(1024)
                if response:
                    self.message_received.emit(f"[TCP 응답] {response.decode('utf-8')}")
                    
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.sendto(self.message.encode('utf-8'), (self.host, self.port))
                self.status_changed.emit(f"UDP 메시지 전송 완료: {self.host}:{self.port}")
                
        except Exception as e:
            self.status_changed.emit(f"송신 오류: {str(e)}")
        finally:
            if self.socket:
                self.socket.close()
                
    def receive_data(self):
        try:
            if self.protocol == "tcp":
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.socket.bind((self.host, self.port))
                self.socket.listen(5)
                self.status_changed.emit(f"TCP 서버 시작: {self.host}:{self.port}")
                
                while self.running:
                    try:
                        self.socket.settimeout(1.0)
                        client_socket, addr = self.socket.accept()
                        data = client_socket.recv(1024)
                        if data:
                            message = data.decode('utf-8')
                            self.message_received.emit(f"[TCP 수신 {addr}] {message}")
                            # 에코 응답
                            client_socket.send(f"Echo: {message}".encode('utf-8'))
                        client_socket.close()
                    except socket.timeout:
                        continue
                        
            else:  # UDP
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.socket.bind((self.host, self.port))
                self.status_changed.emit(f"UDP 서버 시작: {self.host}:{self.port}")
                
                while self.running:
                    try:
                        self.socket.settimeout(1.0)
                        data, addr = self.socket.recvfrom(1024)
                        message = data.decode('utf-8')
                        self.message_received.emit(f"[UDP 수신 {addr}] {message}")
                    except socket.timeout:
                        continue
                        
        except Exception as e:
            self.status_changed.emit(f"수신 오류: {str(e)}")
        finally:
            if self.socket:
                self.socket.close()
                
    def stop(self):
        self.running = False
        if self.socket:
            self.socket.close()


class NetworkTestApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("TCP/UDP 송수신 테스트")
        self.setGeometry(100, 100, 800, 600)
        
        self.network_thread = None
        self.config_file = "config.json"
        
        self.init_ui()
        self.load_config()
        
    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # 상단 컨트롤 영역
        control_widget = QWidget()
        control_layout = QGridLayout(control_widget)
        
        # 모드 선택 (송신/수신)
        mode_group = QGroupBox("모드 선택")
        mode_layout = QHBoxLayout(mode_group)
        
        self.mode_group = QButtonGroup()
        self.send_radio = QRadioButton("송신")
        self.receive_radio = QRadioButton("수신")
        self.send_radio.setChecked(True)
        
        self.mode_group.addButton(self.send_radio, 0)
        self.mode_group.addButton(self.receive_radio, 1)
        
        mode_layout.addWidget(self.send_radio)
        mode_layout.addWidget(self.receive_radio)
        
        # 프로토콜 선택 (TCP/UDP)
        protocol_group = QGroupBox("프로토콜")
        protocol_layout = QHBoxLayout(protocol_group)
        
        self.protocol_group = QButtonGroup()
        self.tcp_radio = QRadioButton("TCP")
        self.udp_radio = QRadioButton("UDP")
        self.tcp_radio.setChecked(True)
        
        self.protocol_group.addButton(self.tcp_radio, 0)
        self.protocol_group.addButton(self.udp_radio, 1)
        
        protocol_layout.addWidget(self.tcp_radio)
        protocol_layout.addWidget(self.udp_radio)
        
        # 주소와 포트
        address_group = QGroupBox("연결 정보")
        address_layout = QGridLayout(address_group)
        
        address_layout.addWidget(QLabel("주소:"), 0, 0)
        self.host_edit = QLineEdit("127.0.0.1")
        address_layout.addWidget(self.host_edit, 0, 1)
        
        address_layout.addWidget(QLabel("포트:"), 1, 0)
        self.port_edit = QLineEdit("8888")
        address_layout.addWidget(self.port_edit, 1, 1)
        
        # 송신 메시지
        message_group = QGroupBox("송신 메시지")
        message_layout = QVBoxLayout(message_group)
        
        self.message_edit = QTextEdit()
        self.message_edit.setMaximumHeight(100)
        self.message_edit.setPlainText("Hello, Network!")
        message_layout.addWidget(self.message_edit)
        
        # 버튼들
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("시작")
        self.start_button.clicked.connect(self.start_network)
        
        self.stop_button = QPushButton("정지")
        self.stop_button.clicked.connect(self.stop_network)
        self.stop_button.setEnabled(False)
        
        self.clear_log_button = QPushButton("로그 지우기")
        self.clear_log_button.clicked.connect(self.clear_log)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.clear_log_button)
        button_layout.addStretch()
        
        # 레이아웃 배치
        control_layout.addWidget(mode_group, 0, 0)
        control_layout.addWidget(protocol_group, 0, 1)
        control_layout.addWidget(address_group, 1, 0, 1, 2)
        control_layout.addWidget(message_group, 2, 0, 1, 2)
        
        # 로그 영역
        log_group = QGroupBox("로그")
        log_layout = QVBoxLayout(log_group)
        
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setFont(QFont("Consolas", 9))
        log_layout.addWidget(self.log_edit)
        
        # 메인 레이아웃에 추가
        main_layout.addWidget(control_widget)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(log_group, 1)  # 로그 영역이 더 많은 공간을 차지하도록
        
        # 시그널 연결
        self.send_radio.toggled.connect(self.on_mode_changed)
        self.receive_radio.toggled.connect(self.on_mode_changed)
        
    def on_mode_changed(self):
        is_send_mode = self.send_radio.isChecked()
        self.message_edit.setEnabled(is_send_mode)
        
    def start_network(self):
        try:
            mode = "send" if self.send_radio.isChecked() else "receive"
            protocol = "tcp" if self.tcp_radio.isChecked() else "udp"
            host = self.host_edit.text().strip()
            port = int(self.port_edit.text().strip())
            message = self.message_edit.toPlainText()
            
            if not host:
                QMessageBox.warning(self, "경고", "주소를 입력해주세요.")
                return
                
            if port < 1 or port > 65535:
                QMessageBox.warning(self, "경고", "포트 번호는 1-65535 범위여야 합니다.")
                return
                
            if mode == "send" and not message:
                QMessageBox.warning(self, "경고", "송신할 메시지를 입력해주세요.")
                return
            
            # 설정 저장
            self.save_config()
            
            # 네트워크 스레드 시작
            self.network_thread = NetworkThread(mode, protocol, host, port, message)
            self.network_thread.message_received.connect(self.on_message_received)
            self.network_thread.status_changed.connect(self.on_status_changed)
            self.network_thread.finished.connect(self.on_thread_finished)
            
            self.network_thread.start()
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            self.add_log(f"=== {mode.upper()} 모드 {protocol.upper()} 시작 ===")
            
        except ValueError:
            QMessageBox.warning(self, "경고", "포트 번호는 숫자여야 합니다.")
        except Exception as e:
            QMessageBox.critical(self, "오류", f"시작 중 오류 발생: {str(e)}")
            
    def stop_network(self):
        if self.network_thread and self.network_thread.isRunning():
            self.network_thread.stop()
            self.network_thread.wait(3000)  # 3초 대기
            
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.add_log("=== 중지됨 ===")
        
    def on_message_received(self, message):
        self.add_log(message)
        
    def on_status_changed(self, status):
        self.add_log(status)
        
    def on_thread_finished(self):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        
    def add_log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}"
        self.log_edit.append(log_message)
        
    def clear_log(self):
        self.log_edit.clear()
        
    def save_config(self):
        config = {
            "mode": "send" if self.send_radio.isChecked() else "receive",
            "protocol": "tcp" if self.tcp_radio.isChecked() else "udp",
            "host": self.host_edit.text(),
            "port": self.port_edit.text(),
            "message": self.message_edit.toPlainText()
        }
        
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.add_log(f"설정 저장 실패: {str(e)}")
            
    def load_config(self):
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                
            # 모드 설정
            if config.get("mode") == "send":
                self.send_radio.setChecked(True)
            else:
                self.receive_radio.setChecked(True)
                
            # 프로토콜 설정
            if config.get("protocol") == "tcp":
                self.tcp_radio.setChecked(True)
            else:
                self.udp_radio.setChecked(True)
                
            # 연결 정보 설정
            self.host_edit.setText(config.get("host", "127.0.0.1"))
            self.port_edit.setText(config.get("port", "8888"))
            self.message_edit.setPlainText(config.get("message", "Hello, Network!"))
            
            self.add_log("이전 설정을 불러왔습니다.")
            
        except FileNotFoundError:
            self.add_log("설정 파일이 없습니다. 기본값을 사용합니다.")
        except Exception as e:
            self.add_log(f"설정 불러오기 실패: {str(e)}")
            
    def closeEvent(self, event):
        self.save_config()
        if self.network_thread and self.network_thread.isRunning():
            self.network_thread.stop()
            self.network_thread.wait(3000)
        event.accept()


def main():
    app = QApplication(sys.argv)
    
    # 애플리케이션 정보 설정
    app.setApplicationName("TCP/UDP 테스트")
    app.setApplicationVersion("1.0")
    app.setOrganizationName("NetworkTest")
    
    window = NetworkTestApp()
    window.show()
    
    return app.exec()


if __name__ == "__main__":
    sys.exit(main()) 