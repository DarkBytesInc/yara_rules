rule Win_Trojan_NSIS_11
{
strings:
	$a0 = { 7300fea63500fe1a235c4343656e7465 }
	$a1 = { 646f776e6c6f616400fd95800061702e6578650073702e6578650073657474696e }

condition:
	$a0 and $a1
}

        
