rule Win_Trojan_V_35
{
strings:
	$a0 = { 80c5108ec10650be00015631ffb90b01f3a4bd2301b9e600fa87ec5b5831d85049e2f8691d706b224adf0506c41a05b9f8a2740776073e1f881e4a53c24d }

condition:
	$a0
}

        
