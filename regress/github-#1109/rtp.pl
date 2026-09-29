# From port 28960 (in the SDP of uac.xml), send a 30 ms PCMU packet,
# 12 + 240 bytes, to the port every 10 ms, and print the size of the
# first echo (0: none in 500 ms).
use Socket; use Time::HiRes qw(time);
socket(S, PF_INET, SOCK_DGRAM, 17) || die($!);
setsockopt(S, SOL_SOCKET, SO_REUSEADDR, 1);
bind(S, pack_sockaddr_in(28960, inet_aton("127.0.0.1"))) || die($!);
$to = pack_sockaddr_in($ARGV[0], inet_aton("127.0.0.1"));
$start = time;
for ($seq = 0; time - $start < 0.5; $seq++) {
    send(S, pack("nnNN", 0x8000, $seq, 240 * $seq, 1) . ("\xff" x 240), 0, $to);
    $r = ""; vec($r, fileno(S), 1) = 1;
    if (select($r, undef, undef, 0.01) > 0) {
        recv(S, $echo, 2048, 0);
        print length($echo), "\n";
        exit;
    }
}
print "0\n";
