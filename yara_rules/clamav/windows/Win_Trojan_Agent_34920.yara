rule Win_Trojan_Agent_34920
{
strings:
	$a0 = { 30b2add5bf28f2fe3622ddca313fdbed2521be8e6c1f82ed6d6d9acb289b6b00f13dfb8d733a9498276c57d35fbbbbda3d72f4e0171efbb17f2c09c11b128d8d1b22b5c7cbfbb16f1e42c0d9373ec5c59fe2af754b23bc9d7663 }

condition:
	$a0
}

        
