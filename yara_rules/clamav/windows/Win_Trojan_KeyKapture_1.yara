rule Win_Trojan_KeyKapture_1
{
strings:
	$a0 = { 063f0594051e8cd8488ed8c60600005a812e0300c000812e1200c00033c08ed8832e130403a11304b106d3e02d1000 }

condition:
	$a0
}

        
