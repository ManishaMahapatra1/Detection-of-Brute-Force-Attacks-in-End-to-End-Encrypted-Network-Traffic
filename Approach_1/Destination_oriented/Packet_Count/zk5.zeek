#!/usr/bin/env zeek
#dest-oriented_packet_count_https.zeek

module HTTPSPacketCountBruteForce;

export {
  # Protocol name
  const proto = "HTTPS";

  # Service port
  const service_port = 443/tcp;
}

@load base/frameworks/notice
@load base/frameworks/sumstats

export {
  redef enum Notice::Type += {
    ## Indicates that a host has been identified as performing a brute force attack
    Brute_Forcing,
  };

  # Max-length packet
  const full_packet_len = 16406;
}

export {
  # Duration of a single epoch to count
  const epoch_len = 10min;

  # The threshold for the number of equal-sized responses to the same origin
  const brute_threshold = 10;
}

event zeek_init() &priority=-101 {
  # send a notice to make sure notice.log is created
  print(fmt("packet-count brute-force script loaded for protocol %s (%s)", proto, service_port));
  NOTICE([$note=Brute_Forcing,
          $msg=fmt("packet-count brute-force script loaded for protocol %s (%s)", proto, service_port)]);
}

event zeek_init() &priority=5 {
  local reducer = SumStats::Reducer($stream="HTTPSPacketCountBruteForce packet observed", $apply=set(SumStats::SUM));

  SumStats::create([
    $name = "counting HTTPSPacketCountBruteForce packets", $epoch = epoch_len, $reducers = set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local sum = result["HTTPSPacketCountBruteForce packet observed"]$sum;
      if (sum >= brute_threshold) {
        NOTICE([$note=Brute_Forcing,
                $msg=fmt("%s appears to be brute-forcing/brute-forced %s (seen %f packets).", key$host, proto, sum),
                $src=key$host]);
      }
    }]);
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;

  SumStats::observe("HTTPSPacketCountBruteForce packet observed",
    SumStats::Key($host=c$id$resp_h),
    SumStats::Observation($num=1));
}
