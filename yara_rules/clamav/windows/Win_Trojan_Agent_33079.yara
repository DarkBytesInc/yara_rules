rule Win_Trojan_Agent_33079
{
strings:
	$a0 = { c808205f83f906762d2ad0ffffffffa21de260bba8205c1961e6c786bf810c9c50e73a3b8d164356ee9890aec57353ff6ffcff9bfe4010423663373e0840a3413ae78bff04205579da1e }

condition:
	$a0
}

        
