rule Win_Trojan_Bancos_1738
{
strings:
	$a0 = { cf063419c0b62b3839641c76c2fe8bb2ad1a6a59066305d1f7fffc412250d7cb91a69c0749628efec4b3d411fd7d7de21dae43400e9c279fa67b220f5581d07c939123283e6e }

condition:
	$a0
}

        
