rule Win_Trojan_V_115
{
strings:
	$a0 = { 03008bf08b84f700a300018b84f900a30201b430cd213c007503e9d000b42fcd21899c4401b41a8bd681c21401cd }

condition:
	$a0
}

        
