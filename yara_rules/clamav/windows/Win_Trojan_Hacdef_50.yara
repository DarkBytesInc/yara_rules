rule Win_Trojan_Hacdef_50
{
strings:
	$a0 = { 9e272de451ffadc089ff4a61b3614d7972c3fde289ff011889014ad89856a3c0a54663c08aff4a0c8be74c2d6e268fc252e94c2dce260fc252e94c2dae271fc252e94c2e0e26ede451ffadc089ff4911b3114b7972c32de289ff }

condition:
	$a0
}

        
