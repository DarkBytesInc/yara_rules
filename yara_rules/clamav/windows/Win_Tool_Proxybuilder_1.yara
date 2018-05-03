rule Win_Tool_Proxybuilder_1
{
strings:
	$a0 = { 50726f7879206275696c646572 }
	$a1 = { 746d702e646c6c0070726f78792e657865 }

condition:
	$a0 and $a1
}

        
