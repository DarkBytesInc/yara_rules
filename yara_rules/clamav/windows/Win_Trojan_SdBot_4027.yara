rule Win_Trojan_SdBot_4027
{
strings:
	$a0 = { 07c88f780980d358bd76bf79b408ef92bff3441a9d2482c7c5a8d4747649befbdb3cd3e2776a66612b5d0dac45fd15d62a2f5bd1d9a78b5a8f038f48d9f9206475ff4aebbbfd88b8e6d6fa737a001d143add74acd387 }

condition:
	$a0
}

        
