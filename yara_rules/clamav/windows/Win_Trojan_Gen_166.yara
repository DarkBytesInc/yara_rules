rule Win_Trojan_Gen_166
{
strings:
	$a0 = { 06019a0d00a4005589e531c09acd0206019a5c0d0601b86400509ac70c06013d4d007503e81bf9b00050bf7e04 }

condition:
	$a0
}

        
