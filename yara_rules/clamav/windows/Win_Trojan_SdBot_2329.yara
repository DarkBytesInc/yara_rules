rule Win_Trojan_SdBot_2329
{
strings:
	$a0 = { c0d234bab533b95f3beddab073f4c0048c4265f84464ff068b8cf3617d078fe2aafe119fa065a2a9d9ae592a32419c02c912c188217e1213f128d09fb56a60e2e5081da767da2015ba9d2afb80f3ebf3db6aed0342 }

condition:
	$a0
}

        
