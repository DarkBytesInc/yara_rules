rule Win_Trojan_Nostardamus_17
{
strings:
	$a0 = { b8409dffe0cc85f783e65481f94c05f585dfcc13daf9cc909090909090909090909090909090909090909090909090 }

condition:
	$a0
}

        
