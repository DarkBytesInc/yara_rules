rule Xls_Trojan_Cartel_1
{
strings:
	$a0 = { 4966204d6f6e7468284e6f7729203d20323320416e6420446179284e6f7729203d2035205468656e2043616c6c20626c75 }
	$a1 = { 6174696f6e2e5374617274757050617468202620225c222026206372797074282273686f66642f796d722f6360722229 }
	$a2 = { 66204469722864767029203d20647770205468656e20436f75 }

condition:
	$a0 and $a1 and $a2
}

        