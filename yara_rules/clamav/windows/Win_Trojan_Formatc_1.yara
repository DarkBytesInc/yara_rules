rule Win_Trojan_Formatc_1
{
strings:
	$a0 = { 2e77726974656c696e652822666f726d6174633a2f752f632f732f6175746f746573743e6e756c2229 }

condition:
	$a0
}

        
