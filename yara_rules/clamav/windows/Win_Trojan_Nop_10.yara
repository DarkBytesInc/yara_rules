rule Win_Trojan_Nop_10
{
strings:
	$a0 = { 51236901690c6c01002467b780056c0000126c00000664 }
	$a1 = { 5167c2806725800506076a093a4175746f4f70656e126a094e6f726d616c3a4353645167c2806725800506076a043a435346126a0f4e6f726d616c3a46696c654f70656e65036f7073 }

condition:
	$a0 and $a1
}

        