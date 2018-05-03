rule Doc_Trojan_Outbreak_7
{
strings:
	$a0 = { 57726924203d20224d6f546142612d4a22205468656e }
	$a1 = { 576f726442617369632e43616c6c202256495255533322 }

condition:
	$a0 and $a1
}

        
