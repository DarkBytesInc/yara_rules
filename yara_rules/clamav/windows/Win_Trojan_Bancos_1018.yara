rule Win_Trojan_Bancos_1018
{
strings:
	$a0 = { 04719611e3fbafe5bf7fafa51a23193b1b8af854f132ea6079cf910d926efe029ed95158e000942a23738c491a2bfb9cc8e194c96fbf9c5ae95b33d3f15166bb1f6f45e1fbbbd7f2bd099a5036a82ca242f9961b345d5086 }

condition:
	$a0
}

        
