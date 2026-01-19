from scapy.all import *

print("\nNТест: Быстрое сканирование 15 портов")
for port in range(1000, 1015):  # Порты 1000-1014
    packet = IP(dst="192.168.1.1")/TCP(dport=port, flags="S")
    send(packet, verbose=0)
    print(f"   Отправлен SYN на порт {port}")
    time.sleep(0.1) 
    
