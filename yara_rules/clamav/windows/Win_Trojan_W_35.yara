rule Win_Trojan_W_35
{
strings:
	$a0 = { 87d192b80042cd21c32056697275735f666f725f57696e646f7773202076312e3420 }

condition:
	$a0
}

        
