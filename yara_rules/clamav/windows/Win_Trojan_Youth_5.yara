rule Win_Trojan_Youth_5
{
strings:
	$a0 = { cd21eb0644594502e804b82135cd21891e42028c0644028cc8488ed8ac803e00005a7533833e03004890722b83 }

condition:
	$a0
}

        
