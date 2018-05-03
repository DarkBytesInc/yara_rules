rule Doc_Trojan_Outbreak_6
{
strings:
	$a0 = { 4124203d20224f7574427265616b2d4a22205468656e }
	$a1 = { 576f726442617369632e43616c6c20224d6f546142613322 }

condition:
	$a0 and $a1
}

        
