rule Win_Trojan_Small_3834
{
strings:
	$a0 = { 7140949e5717c91e6fc358373803e875fabcb82ea21bd019e544c6de5a6dcd3de362eaa936cb8b1ea03f094383283e596f40eda32f99092af2069961fa06185d6fb5787df27c331f7ed5547eca03eb75fabcb82af43fa4a229 }

condition:
	$a0
}

        
