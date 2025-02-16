import socket
import threading
import termcolor
import ipaddress
from rich.console import Console
from rich.table import Table

console = Console()

# danh sách các cổng phổ biến
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080]

# quét nhiều port
# sử dụng đa luồng để quét ports đồng thời
# hiển thị bảng kết quả
# lưu kết quả vào file (nếu cần)
# target: địa chỉ IP của mục tiêu
# ports: danh sách các cổng cần quét
# save_results: T/F
def scan_ports(target, ports, save_results, protocol):
    """
    Hàm quét các cổng trên mục tiêu 
    """
    console.print(f"\n[*] Bắt đầu quét {target} ({protocol})", style="bold cyan")
    
    # bảng hiển thị kết quả
    table = Table(title=f"Kết quả quét {target} ({protocol})")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Service", style="magenta")
    table.add_column("Status", style="green")

    # khởi tạo đa luồng để quét port
    threads = [] # list lưu trữ luồng
    results = [] # list lưu kết quả (port và service)

    for port in ports:
        thread = threading.Thread(target=scan_port, args=(target, port, results, protocol)) # tạo 1 luồng mới quét cổng
        threads.append(thread) # thêm luồng vào list
        thread.start() # bắt đầu luồng

    for thread in threads:
        thread.join()  # đảm bảo tất cả luồng hoàn thành trước khi hiển thị kết quả

    # hiển thị kết quả
    for port, service in results:
        table.add_row(str(port), service, "Open")

    console.print(table)

    # lưu kết quả vào file 
    if save_results:
        with open("scan_results.txt", "a") as file:
            file.write(f"\nKết quả quét {target} ({protocol}):\n")
            for port, service in results:
                file.write(f"[+] Cổng {port} ({service}) đang mở trên {target}\n")

# kiểm tra xem 1 cổng trên 1 địa chỉ ip đang mở hay không
# ip_address: địa chỉ IP của mục tiêu
# port: cổng cần quét
# results: list lưu kết quả quét (open port và service chạy trên port) 
def scan_port(ip_address, port, results, protocol):
    """
    Hàm quét một cổng cụ thể trên một địa chỉ IP
    """
    try:
        # tạo socket và thiết lập timeout
        # socket sẽ sử dụng giao thức IPv4 (AF_INET) và kiểu kết nối TCP (SOCK_STREAM).
        # thiết lập timeout cho kết nối là 0.5s. Nếu kết nối không thành công trong thời gian này, bỏ qua và chuyển sang cổng tiếp theo
        if protocol == "TCP":
            # tạo socket TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            # kết nối đến cổng trên địa chỉ IP mục tiêu
            # hàm connect_ex return 0 nếu kết nối thành công (cổng mở), ngược lại return một mã lỗi (cổng đóng hoặc không phản hồi)
            result = sock.connect_ex((ip_address, port))
        else: 
            # tạo socket UDP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.5)
            sock.sendto(b'', (ip_address, port))
            try:
                data, addr = sock.recvfrom(1024)
                result = 0  # cổng mở
            except socket.timeout:
                result = 1  # cổng đóng hoặc không phản hồi

        # kiểm tra kết quả kết nối
        if result == 0:
            try:
                # lấy tên service đang chạy trên cổng đó
                service = socket.getservbyport(port, protocol.lower()) 
            except:
                # không xác định được service 
                service = "Unknown"
            # lưu kết quả (port và service) vào danh sách results
            results.append((port, service))
            console.print(f"[+] Cổng {port} ({service}) đang mở trên {ip_address} ({protocol})", style="yellow")
        # đóng kết nối socket sau khi kiểm tra
        sock.close()
    except:
        pass

def parse_targets(target_input):
    """
    Phân tích chuỗi đầu vào để xác định danh sách địa chỉ IP cần quét.
    Hỗ trợ:
    - Địa chỉ IP đơn
    - Dải IP (VD: 192.168.1.1-192.168.1.10)
    - CIDR (VD: 192.168.1.0/24)
    """
    targets = [] # danh sách các địa chỉ IP cần quét
    if "-" in target_input:  # nếu input là một IP range
        start_ip, end_ip = target_input.split("-") # tách chuỗi input
        start_ip = ipaddress.IPv4Address(start_ip.strip()) # chuyển địa chỉ IP sang dạng IPv4Address
        end_ip = ipaddress.IPv4Address(end_ip.strip()) # chuyển địa chỉ IP sang dạng IPv4Address

        # duyêt qua các giá trị số nguyên 
        for ip_int in range(int(start_ip), int(end_ip) + 1):
            targets.append(str(ipaddress.IPv4Address(ip_int))) # chuyển int sang ip_address và thêm vào list

    elif "/" in target_input:  # định dạng CIDR
        network = ipaddress.ip_network(target_input.strip(), strict=False) # tạo ip_network từ chuỗi CIDR, cho phép IP không hợp lệ
        targets = [str(ip) for ip in network.hosts()] # duyệt qua các IP trong mạng CIDR và thêm vào list

    else:  # IP đơn
        targets.append(target_input.strip())

    return targets

if __name__ == "__main__":
    target_input = input("[*] Nhập địa chỉ IP cần quét (IP, dải IP, CIDR): ")
    protocol_input = input("[*] Chọn giao thức quét (1: TCP, 2: UDP): ")
    protocol = "TCP" if protocol_input == "1" else "UDP"
    mode_input = input("[*] Chọn chế độ quét (1: Quét nhanh, 2: Quét đầy đủ): ")

    if mode_input == "1":
        console.print("[*] Đã chọn chế độ quét nhanh (Bắt đầu quét các cổng phổ biến))", style="blue")
        ports = COMMON_PORTS
    else:
        num_ports_input = int(input("[*] Nhập số lượng cổng muốn quét: "))
        ports = list(range(1, num_ports_input + 1))

    save_choice = input("[*] Bạn có muốn lưu kết quả quét không? (y/n): ").lower()
    save_results = save_choice == "y"

    targets = parse_targets(target_input)

    console.print(f"[*] Đang quét {len(targets)} mục tiêu...", style="cyan")

    for target in targets:
        scan_ports(target, ports, save_results, protocol)
