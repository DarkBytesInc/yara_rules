rule Win_Trojan_DJengine_2
{
strings:
	$a0 = { 54686973206973206120444a2076697275732056657220312e305e81ee03008bfe83e7f08bc7b104d3e88cc903c1 }

condition:
	$a0
}

        
