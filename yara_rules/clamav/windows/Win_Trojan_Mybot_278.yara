rule Win_Trojan_Mybot_278
{
strings:
	$a0 = { 6878307275ee051353ffe02962210801a8002298000084fd003f2334e1957e1e37d7c0b0300731931345010030e7015b3a1100e9f3ffaff323004c14547c96b4a17703000000f0faffdbfba1ed77a9af0f410062c6fc774e494c5349534741 }

condition:
	$a0
}

        