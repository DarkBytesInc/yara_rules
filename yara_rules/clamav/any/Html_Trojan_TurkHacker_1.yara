rule Html_Trojan_TurkHacker_1
{
strings:
	$a0 = { 7475726b697368206861636b6572[33]69736b6f7270697478 }

condition:
	$a0
}

        
