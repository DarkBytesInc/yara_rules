rule Win_Spyware_Banker_2666
{
strings:
	$a0 = { 0ced32539b67b2d86d74a2a2a5655bf0e16a2813995861d3c59dcb287a1005ad6a4133af1be635f32fed4adb71ff239891eacc38a08dc130eabde7ad723ea93f7111f5f05611bcf98f5c1992e8c1fb27a282e4685cd7d4b95d4dc36fb11b63fc92e9 }

condition:
	$a0
}

        
