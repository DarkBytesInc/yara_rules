rule Win_Trojan_Sinowal_48
{
strings:
	$a0 = { 6a006884a340006a006884a340006a009c579090 }
	$a1 = { 66006a00670061006700640064006100650064 }

condition:
	$a0 and $a1
}

        
