rule Win_Trojan_Asscom_1
{
strings:
	$a0 = { 454d2059b44eba9c01cd21724feb0790b44fcd217246ba9e00b8023dcd2172f08bd88b0e9a00b43fbaa401cd21a100013906a401741e33c933d2b80042cd21b440ba0001b9a4 }

condition:
	$a0
}

        
