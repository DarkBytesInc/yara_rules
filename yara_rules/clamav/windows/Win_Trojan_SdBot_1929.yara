rule Win_Trojan_SdBot_1929
{
strings:
	$a0 = { bfdae8089a0e8b130c8c8bfc8bffcbe84e68db50931889519d0fdad05734d7390aeb8ff14830c48bcbdc51ca841ae8fbd4584d48c1cbe828a741dd11bdc336cb48b1481a93c041e8242699b1c444323e18bed6d07a4fc403c6fc7798583a40 }

condition:
	$a0
}

        
