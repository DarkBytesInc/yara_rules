rule Win_Trojan_IRC_Script_110
{
strings:
	$a0 = { 696620282431203d20666c6f6f642e6e29207b20736f636b7772697465202d6e7420 }
	$a1 = { 697465202d6e742024736f636b6e616d65204e49434b20247228612c7a2920242b20247228612c7a2920242b20247228612c7a2920242b20247228612c7a29 }

condition:
	$a0 and $a1
}

        