rule Win_Spyware_Banker_2110
{
strings:
	$a0 = { 28dd82f3e8a6c354937886c5b039a3ea53d27f91e3fd61b683bbb9877bacee4082aa4eb18a37aa2093d6eb25bb44074f6d1e9cc127dbfb34b9687cd7ab09f117bf9790f78f808ab0110c48c4539ff39483fbe30e3e2e84b0f30bb63743ba27f7ec315948e95723213dcded617dbfd9c46270f7691189ff0d701001e942 }

condition:
	$a0
}

        