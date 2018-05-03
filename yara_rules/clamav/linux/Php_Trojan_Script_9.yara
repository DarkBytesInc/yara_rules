rule Php_Trojan_Script_9
{
strings:
	$a0 = { 3c3f206576616c28677a696e666c617465286261736536345f6465636f64652827 }
	$a1 = { 27292929 }

condition:
	$a0 and $a1
}

        
