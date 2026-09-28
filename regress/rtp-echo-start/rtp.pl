# From port 28900 (in the SDP of uac.xml), send an RTP packet to the
# port every 2 ms, and print how long after the first one the first
# echo comes in, in ms (999: none in 500 ms).
use Socket; use Time::HiRes qw(time);
socket(S, PF_INET, SOCK_DGRAM, 17) || die($!);
setsockopt(S, SOL_SOCKET, SO_REUSEADDR, 1);
bind(S, pack_sockaddr_in(28900, inet_aton("127.0.0.1"))) || die($!);
$to = pack_sockaddr_in($ARGV[0], inet_aton("127.0.0.1"));
$start = time;
for ($seq = 0; time - $start < 0.5; $seq++) {
    send(S, pack("nnNN", 0x8000, $seq, 160 * $seq, 1) . ("\xff" x 160), 0, $to);
    $r = ""; vec($r, fileno(S), 1) = 1;
    if (select($r, undef, undef, 0.002) > 0) {
        printf("%d\n", 1000 * (time - $start));
        exit;
    }
}
print "999\n";
