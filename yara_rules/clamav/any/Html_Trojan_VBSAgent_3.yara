rule Html_Trojan_VBSAgent_3
{
strings:
	$a0 = { 6d657373656e6765722e686f746d61696c2e636f6d3e3e633a5c77696e646f77735c73797374656d33325c647269766572735c6574635c686f737473223e3e633a5c2566696c656e616d65252e62617420666f726d617420633a2070617573652073687574646f776e202d73202d7420323030202d63 }

condition:
	$a0
}

        