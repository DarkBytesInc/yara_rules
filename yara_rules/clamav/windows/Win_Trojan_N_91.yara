rule Win_Trojan_N_91
{
strings:
	$a0 = { 4300070654466f726d31c00c4300002542003b00066e6f6e756b65000090558bec6a006a0053568bf18bd833c05568080f430064ff3064892068200f43008d55f88bc6e8 }

condition:
	$a0
}

        