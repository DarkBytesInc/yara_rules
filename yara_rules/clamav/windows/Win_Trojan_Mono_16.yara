rule Win_Trojan_Mono_16
{
strings:
	$a0 = { 908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908bd2908b }

condition:
	$a0
}

        