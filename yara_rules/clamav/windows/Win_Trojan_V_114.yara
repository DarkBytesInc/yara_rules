rule Win_Trojan_V_114
{
strings:
	$a0 = { 03008bf0508b84f100a300018b84f300a30201b430cd213c007503e9c800b42fcd21899c3e01b41a8bd681c20e01 }

condition:
	$a0
}

        
