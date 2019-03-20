# mqtt_detection_with_BroIDS
MQTT is an IoT protocol that has a type of suspicious activity where a device may subscribe to all "feeds"
To detect a subscribe all packet, you must help Bro to identify the structure of a MQTT packet (Note that MQTT messages can be stacked into one tcp packet).

An sample structure of MQTT packet looks like this: 0x82 0x06 0xAD 0x38 0x00 0x01 0x23 0x00

0x82 (1 byte): defines the type of MQTT packet (this case it's a Subcribe packet)

0xAD 0x38 (2 bytes): the variable head

0x00 0x01 (2 bytes): the payload length

0x06 (1 byte): the actual size of the packet content

0x23 (Unlimited byte): the actual payload

0x00 (1 byte): Quality of Service (QoS)

Terminal command: bro -r mqtt_traffic.pcap mqtt.bro where mqtt_traffic.pcap is your pcap file that contains mqtt traffic.
