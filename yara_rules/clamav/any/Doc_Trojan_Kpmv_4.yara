rule Doc_Trojan_Kpmv_4
{
strings:
	$a0 = { 51203d204c794e4169202b20546b4f486a202b204c65465269202b204a70534d72202b204178454766202b204d6b52506c202b20447855526d202b20527544546b202b204769434673202b20557a50516f202b20527a424677202b2053 }

condition:
	$a0
}

        