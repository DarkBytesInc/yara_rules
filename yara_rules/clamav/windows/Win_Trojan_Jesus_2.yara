rule Win_Trojan_Jesus_2
{
strings:
	$a0 = { 30f682ce8590902bf681c68d3721ff28d280ca5dfa31c981c97c0281c2ec83d0c29090f7d27e0032d1eb02bbaef83194afc922d283c602e2e2f9f67fd8d01bfe0dcae5fc6d5af5023f32f4853946f7c5848af25c4304158e }

condition:
	$a0
}

        
