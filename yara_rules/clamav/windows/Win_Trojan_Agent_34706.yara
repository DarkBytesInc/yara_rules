rule Win_Trojan_Agent_34706
{
strings:
	$a0 = { 7d053d3571b09df6d0f6d066a9f9ef505152538d44241050555657c0cfb85052516ade59595a5872067a047c }

condition:
	$a0
}

        
