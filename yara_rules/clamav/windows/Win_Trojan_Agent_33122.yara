rule Win_Trojan_Agent_33122
{
strings:
	$a0 = { 9c87c94142e8000000005b3bcb4ef7da8bc3555984c6f381ebb810010033f97900fd534281c03d0000006800000000 }

condition:
	$a0
}

        
