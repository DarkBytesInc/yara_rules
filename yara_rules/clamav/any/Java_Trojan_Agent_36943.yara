rule Java_Trojan_Agent_36943
{
strings:
	$a0 = { cafebabe }
	$a1 = { 4275726b696e6f476f736f }

condition:
	$a0 and $a1
}

        
