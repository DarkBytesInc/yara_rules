rule Doc_Trojan_Golden_6
{
strings:
	$a0 = { 4f70656e202822633a5c77696e646f77735c77696e73746172742e626174222920466f7220496e70757420417320 }
	$a1 = { 4d7367426f782022596f757220696e66656374656420776974682074686520474f4c44454e205669727573202843293139 }

condition:
	$a0 and $a1
}

        