# Not needed, but for programming best practice
@load base/bif/event.bif.bro
@load base/frameworks/logging/postprocessors


module Mqtt;
export {
  redef enum Notice::Type += { Mqtt::Subscribe };
  redef enum Log::ID += { LOG };
  type Info: record {
    ts: time &log;
    src_ip: addr &log;
    src_port: port &log;
    dst_ip: addr &log;
    dst_port: port &log;
    length: count &log;
    payload: string &log;
  };
}
 
 
# This function parses a single packet of Mqtt data
# Returns the length of the packet while raising alert if there is a subscribe all request
function mqtt_parse_packet(c: connection, remaining_contents: string) : count {
	# Get the actual length of the subscribe packet
    local rem_len = 
        bytestring_to_count(
            hexstr_to_bytestring(
                string_to_ascii_hex(
                    sub_bytes(remaining_contents, 2, 1)
                )
            )
        );


    # Get the actual content in the Subscribe packet   
    local payload_content =
        hexstr_to_bytestring(
            string_to_ascii_hex(
                sub_bytes(remaining_contents, 7, (rem_len - 4 - 1))
            )
        );

    # Define the context of mqtt.log
    local rec: Mqtt::Info = [
      $ts = network_time(),
      $src_ip = c$id$orig_h,
      $src_port = c$id$orig_p,
      $dst_ip = c$id$resp_h,
      $dst_port = c$id$resp_p,
      $length = rem_len + 2,
      $payload = payload_content
    ];
    # Write the log
    Log::write(Mqtt::LOG, rec);
    
   # Detect MQTT subscribe message (whose type is "0x82")
   if (sub_bytes(remaining_contents, 1, 1) == "\x82") { 
    # Now check if the payload string has a # which indicates a subscribe all
    if ("#" in payload_content){
      NOTICE([
        $note = Mqtt::Subscribe,
        $msg = fmt("%s attempts to subscribe to all topics.", c$id$orig_h)
      ]);
    }
  }
 
  return (rem_len + 2);
}

# Detect a mqtt connection to port 1883
# The while loop handles multiple mqtt packets being present in a single
# contents string and indexes through the string for the Mqtt parser 
event packet_contents (c: connection, contents: string) {
  if (c$id$resp_p == 1883/tcp) {
	local index = 1;
	while (index <= |contents|) {
		local remain_length = mqtt_parse_packet(c, sub_bytes(contents, index, |contents|));
		index = index + remain_length;
	}
  }
}
 
# This event is handled at a priority higher than zero so that if
# users modify this stream in another script, they can do so at the
# default priority of zero.
event bro_init() &priority=5 {
  Log::create_stream(Mqtt::LOG, [$columns=Info, $path="mqtt"]);
}

