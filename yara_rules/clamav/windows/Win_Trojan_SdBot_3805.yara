rule Win_Trojan_SdBot_3805
{
strings:
	$a0 = { 8093b4ce9e57d6f3e7fa0809abe21019e4ea06e9b98c732cb778b6f511bfd8be8d1cafe7c3365c48a3a0b5ad62505e4616273b6937fbc0bce62b0961ca8686078fbadcddcf043fcff3247923b68d4c475cc68e91e24a05afe4f6858a2ac6a69a646a }

condition:
	$a0
}

        
