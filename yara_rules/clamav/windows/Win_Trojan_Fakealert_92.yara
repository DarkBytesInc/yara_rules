rule Win_Trojan_Fakealert_92
{
strings:
	$a0 = { 96a9c6df63273950a1b6fdfb8fd63ea962b38ab0b94605f68b7b84b83a6ea6b69ab8a415e5749b268cc81818827fc9d94abacc673940c2a442b89c8ac49c9b41a2307f6dcaaf3aea3e87fd3f3848b3da720e8b68dd07adf61a478f8c355842f9bb87b940 }

condition:
	$a0
}

        
