rule Win_Trojan_Krad_2
{
strings:
	$a0 = { c745020200b440b9310299cd2126c74515000026c745170000b440b91c00ba3902cd21b8015726 }

condition:
	$a0
}

        
