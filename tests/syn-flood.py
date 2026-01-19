from scapy.all import *

print("\nТест: SYN-флуд (20 SYN на порт 80)")
for i in range(20):
    packet = IP(dst='192.168.1.1')/TCP(dport=80, flags="S", sport=50000+i)
    send(packet, verbose=0)
    print(f"   Отправлен SYN #{i+1} на порт 80")
    time.sleep(0.05)
