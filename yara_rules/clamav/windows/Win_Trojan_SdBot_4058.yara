rule Win_Trojan_SdBot_4058
{
strings:
	$a0 = { 3c9549de78b20f349a7b858dc1489274e0edeafdb7ef009f37ad6b506a574db87dc0e834448c2a263bf4a531fb23ad033bde268280b27a9101cdcbbd74180fc27ffb3231408b2a71bbb89ef733c70bebb4204060d6f5 }

condition:
	$a0
}

        
