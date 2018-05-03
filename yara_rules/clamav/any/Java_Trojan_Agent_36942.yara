rule Java_Trojan_Agent_36942
{
strings:
	$a0 = { cafebabe }
	$a1 = { 63706e616b63 }

condition:
	$a0 and $a1
}

        
