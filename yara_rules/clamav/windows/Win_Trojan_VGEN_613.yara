rule Win_Trojan_VGEN_613
{
strings:
	$a0 = { 8b2e01018bfe8db63e01a5a433c08ec026380687007526fec48bf00e07c34d4f504520284329202739332062792047 }

condition:
	$a0
}

        
