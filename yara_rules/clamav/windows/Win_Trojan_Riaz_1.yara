rule Win_Trojan_Riaz_1
{
strings:
	$a0 = { 4c0102005a7a5a210046 }
	$a1 = { 29513c380209e06340d110d61c2a2eb873e9b8067ae0457258e04d3850330b415649b2aa04e7a49de733d362c788fd112c4ed3105b }

condition:
	$a0 and $a1
}

        
