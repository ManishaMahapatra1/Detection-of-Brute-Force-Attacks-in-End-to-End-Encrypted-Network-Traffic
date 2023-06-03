#!/usr/bin/env zeek
#orig-oriented_similar_sized_https.zeek

module HTTPSSimilarSizedResponsesBruteForce;

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

  # The threshold for the number of similar-sized responses to the same origin
  const brute_threshold = 750;

  # The deviation up to which sizes are considered similar-sized (in bytes)
  const size_max_deviation = 100;
}

event zeek_init() &priority=-101 {
  # send a notice to make sure notice.log is created
  print(fmt("similar-sized brute-force script loaded for proto %s (%s)", proto, service_port));
  NOTICE([$note=Brute_Forcing,
          $msg=fmt("similar-sized brute-force script loaded for proto %s (%s)", proto, service_port)]);
}

event zeek_init() &priority=15 {
  local reducer = SumStats::Reducer($stream="HTTPSSimilarSizedResponsesBruteForce response size observed", $apply=set(SumStats::TOPK));

  SumStats::create([
    $name = "counting HTTPSSimilarSizedResponsesBruteForce response sizes", $epoch=epoch_len, $reducers=set(reducer),
    $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
      local topk = result["HTTPSSimilarSizedResponsesBruteForce response size observed"]$topk;
      local top: vector of SumStats::Observation = topk_get_top(topk, 10000);

      local size_counts: table[count] of count;

      local source = key$host;
      local attack = F;
      for (v in top) {
        if (key$host != source) {
          print("WARNING: Unexpectedly found multiple addresses in a single SumStats result!");
        }

        local c = topk_count(topk, top[v]);
        size_counts[top[v]$num] = c;
      }
      for (tcp_size in size_counts) {
        local size_count = 0;

        local matching_sizes: set[count];
        for (comp_size in size_counts) {
          if (comp_size < tcp_size) {
              local temp = comp_size;
              comp_size = tcp_size;
              tcp_size = temp;
          }
          local delta = |comp_size - tcp_size|;
          if (delta <= size_max_deviation) {
            size_count += size_counts[comp_size];
            add matching_sizes[comp_size];
          }
        }
        if (size_count >= brute_threshold) {
          NOTICE([$note=Brute_Forcing,
                  $msg=fmt("%s appears to be brute-forcing/brute-forced %s (seen %d similar-sized responses of %d different TCP sizes around %d).", key$host, proto, size_count, |matching_sizes|, tcp_size),
                  $src=key$host]);

          attack = T;
          break;
        }
      }

      if (attack) return;
    }
  ]);
}


event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count, payload: string) {
  # ignore non-service packets
  if (c$id$resp_p != service_port) return;
  # ignore request packets, only treat responses
  if (is_orig) return;
  # ignore empty packets and packets of full length (huge transmissions cause several full-length packets)
  if (len == full_packet_len || len == 0) return;

  SumStats::observe("HTTPSSimilarSizedResponsesBruteForce response size observed",
    SumStats::Key($host=c$id$orig_h),
    SumStats::Observation($num=len));
}
