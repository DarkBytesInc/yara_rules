rule Java_Trojan_Agent_36941
{
strings:
	$a0 = { cafebabe }
	$a1 = { 617274747161 }

condition:
	$a0 and $a1
}

        
