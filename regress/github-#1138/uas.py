# Answer the INVITE that comes to port 26462 with a 180 whose headers
# end without the blank line that should follow them.
import re
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 26462))
s.settimeout(10)
data, peer = s.recvfrom(65535)
hdr = dict(re.findall(r"^(Via|From|To|Call-ID|CSeq): (.*?)\r$", data.decode(), re.M))
s.sendto(("SIP/2.0 180 Ringing\r\n"
          "Via: %(Via)s\r\n"
          "From: %(From)s\r\n"
          "To: %(To)s;tag=1\r\n"
          "Call-ID: %(Call-ID)s\r\n"
          "CSeq: %(CSeq)s\r\n"
          "Content-Length: 0\r\n" % hdr).encode(), peer)
