rule Win_Trojan_Evyl_1
{
strings:
	$a0 = { 08c1c004055623355233460cc7075c737973250f0f0f0f0561616161894704c747082e74706d }

condition:
	$a0
}

        
