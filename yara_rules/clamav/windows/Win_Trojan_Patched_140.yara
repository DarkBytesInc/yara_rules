rule Win_Trojan_Patched_140
{
strings:
	$a0 = { e8765cffff }
	$a1 = { 01c93e0100000000000000000000000000306004018bff558bec000000000000000000000000000000000000000000000000 }

condition:
	$a0 and $a1
}

        