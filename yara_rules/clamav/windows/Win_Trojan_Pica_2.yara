rule Win_Trojan_Pica_2
{
strings:
	$a0 = { 49662028666c61736864726976652e6472697665747970653d31206f7220666c61736864726976652e6472697665747970653d322920616e6420666c61736864 }
	$a1 = { 2e646c6c2e7662732229 }
	$a2 = { 6372656174657465787466696c6528666c61736864726976652e706174682026225c6175746f72756e2e696e6622 }

condition:
	$a0 and $a1 and $a2
}

        