rule Win_Trojan_Katusha3_1
{
strings:
	$a0 = { 45d031d029d20b9504ffffff2395e0feffff09c221c281ea9b000000198504feffff898520feffff3185b4feffff09959cfeffff239564ffffff1395f8feffff29c00b85e0feffff098590feffff483b8534ffffff733dba100900004a81c2a700000021 }

condition:
	$a0
}

        
