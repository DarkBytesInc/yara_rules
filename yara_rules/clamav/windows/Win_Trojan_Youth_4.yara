rule Win_Trojan_Youth_4
{
strings:
	$a0 = { cd21eb0644594102e804b82135cd21891e3f028c0641028cc8488ed8ac803e00005a7530833e0300487229832e }

condition:
	$a0
}

        
