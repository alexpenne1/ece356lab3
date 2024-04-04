**Updates as of 4/4:**
**Added:**
+ sr_handlepacket:
+   Determines if IP packet is UDP type.
+   If UDP, determines if port numbers match RIP packet type.
+   If RIP request, calls send rip response.
+   If RIP response, calls update route table.

+ sr_send_request:
+   Makes the packet structure.
+   Sends packet through each of the interfaces.

+ sr_send_response:
+   Same as above, but adds in entries.

**Need to Do:**
+ Version for RIP packet?
+ Source IP and Ethernets?
+ Next hop parameter?
+ Need to test these two methods before starting timeout and update route table.
