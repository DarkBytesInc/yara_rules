rule Win_Trojan_Startpage_410
{
strings:
	$a0 = { b870320010c7051040001030320010c70514400010d0310010a318400010a31c400010c3 }

condition:
	$a0
}

        
