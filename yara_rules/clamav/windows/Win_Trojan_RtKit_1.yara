rule Win_Trojan_RtKit_1
{
strings:
	$a0 = { a66b97bc9ae65513f00769eabc776902ccaa1ab27368be6d59dab9a10f53597678b898b39007e2e45eeb9517f02b5a1a694f2fdcd17be0c3737bd7c3a0362b56dc9b9030db35993504a96e183945de15 }

condition:
	$a0
}

        
