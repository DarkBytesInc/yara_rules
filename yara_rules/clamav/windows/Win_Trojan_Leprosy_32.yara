rule Win_Trojan_Leprosy_32
{
strings:
	$a0 = { 01008b1e560253e80f00b440ba00015bb99a02cd21e80100c3bb37018a27505832260601505888274350 }

condition:
	$a0
}

        
