rule Win_Trojan_VGEN_441
{
strings:
	$a0 = { 03b9fb0081370e1083c302e2f790e6100e4d8ffd1211f59b10800e9e08820e3e829602132099901e0dea00178386 }

condition:
	$a0
}

        
