rule Win_Trojan_Agent_33722
{
strings:
	$a0 = { a5fbebe81f7d47e08bb2fcbc36e8bab5f7743f1badfa99448d8facfbcefc55a801a078c80e84ce8a6b0f50f275ceb9992f1de6c701ff3aec08c301141ab17d65a9138eb5c2428631a429e1fb3698f6f4fcb906fbdd4d83b3d087113721536c }

condition:
	$a0
}

        
