rule Win_Trojan_Hacdef_14
{
strings:
	$a0 = { 6c6f745c637273732a005c4465766963655c546370005c4465766963655c556470005c003f003f005c }

condition:
	$a0
}

        