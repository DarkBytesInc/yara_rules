rule Win_Trojan_ASP_27
{
strings:
	$a0 = { 282270617373776f726422293d226a756368656e22 }
	$a1 = { 726573756c742b6d6964287374722c692c3129 }

condition:
	$a0 and $a1
}

        
