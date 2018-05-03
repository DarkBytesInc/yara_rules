rule Java_Trojan_Agent_36975
{
strings:
	$a0 = { 6a6176612f6c616e672f537472696e67 }
	$a1 = { 7772697465456d62656464656446696c65 }
	$a2 = { 4c504f5254 }
	$a3 = { 4c484f5354 }

condition:
	$a0 and $a1 and $a2 and $a3
}

        
