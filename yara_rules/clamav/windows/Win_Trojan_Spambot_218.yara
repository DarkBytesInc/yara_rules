rule Win_Trojan_Spambot_218
{
strings:
	$a0 = { 2a6bd985b619ffbff8ffcddc8b05b19e8d90d80c9f5e919b09a09560d0b350e1664da668ffffffffc28d914fcd1a19dfbce9a12629a7f87294b044a7e3d9f9a4916522d3a57002a5ffffffff59c76ed98a98da2e54af8b0855a67954abbb6ea9106be1fca4eefa8464490fc500ff }

condition:
	$a0
}

        
