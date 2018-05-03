rule Email_Trojan_Trojan_603
{
strings:
	$a0 = { 5375626a6563743a20476572656e636961646f722046696e616e636569726f }
	$a1 = { 312d0d0a687474703a2f2f }

condition:
	$a0 and $a1
}

        
