rule Html_Trojan_IRCPredator_1
{
strings:
	$a0 = { 5265674f70656e4b65794100120000004c0041004e00330032002e004400520056 }
	$a1 = { 2000240067006500740074006f006b0028002400690070002c0031002c003400360029 }

condition:
	$a0 and $a1
}

        