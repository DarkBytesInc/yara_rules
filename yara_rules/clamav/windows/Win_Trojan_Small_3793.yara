rule Win_Trojan_Small_3793
{
strings:
	$a0 = { e0b82afb10e97f13352c739070fc94d5852894013d2d545792f02f465e9c7f13b6b12679b7b0204debb3bc463d042e42e5be2898cbe0fc76bee8f4548aebb81c01a079967f6132efc8d7f2a3bee9 }

condition:
	$a0
}

        
