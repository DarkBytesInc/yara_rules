rule Win_Trojan_BAT_103
{
strings:
	$a0 = { 636f70792067656e657369732e65[0-16]67656e657369732e6578652e626174 }

condition:
	$a0
}

        
