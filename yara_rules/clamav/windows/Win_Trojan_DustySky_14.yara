rule Win_Trojan_DustySky_14
{
strings:
	$a0 = { 3f3f203f3f3f3f3f3f203f3f3f3f3f3f3f203f3f3f3f3f203f3f3f3f3f2e657865 }

condition:
	$a0
}

        