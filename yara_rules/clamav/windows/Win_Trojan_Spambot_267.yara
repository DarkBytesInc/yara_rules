rule Win_Trojan_Spambot_267
{
strings:
	$a0 = { 3464e70ed177e83689dbf24e6900e13ffcffff9cb57d4062f11d92cd4040fdb8f7b80f6f16f6a36bb65d29c4f9ff87fbefd0dd9ecfc243ed753f15d5ab635ba5aa423359f6ffffffe1637501011fc91ae4a0cb655b4a7f80f2dee0d58e0859c56dbc94fff0ffffabce7ce648b847 }

condition:
	$a0
}

        
