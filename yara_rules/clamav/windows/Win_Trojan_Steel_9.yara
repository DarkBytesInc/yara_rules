rule Win_Trojan_Steel_9
{
strings:
	$a0 = { 636f707920253020633a5c205c253020636f707920253020643a5c76697275732e626174 }
	$a1 = { 737465656c }

condition:
	$a0 and $a1
}

        
