rule Win_Trojan_Udr_1
{
strings:
	$a0 = { 60e872050000eb3387db90000000000000000000000000000000000000000000000000002003000000400000e00200000000000000000000100300bb3c39440003dd2b9d6039440083bd9847440000899d984744000f85810400008d85a047440050ff95 }
	$a1 = { 8b2c2481ed43394400c3 }

condition:
	$a0 and $a1
}

        