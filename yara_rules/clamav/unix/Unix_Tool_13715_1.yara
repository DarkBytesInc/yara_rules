rule Unix_Tool_13715_1
{
strings:
	$a0 = { 31c9516861646f7768632f7368682f2f657489e366b991016a0558cd8089c3eb0d596a205ab0b56a085e31ffcd80e8eeffffff }

condition:
	$a0
}

        
