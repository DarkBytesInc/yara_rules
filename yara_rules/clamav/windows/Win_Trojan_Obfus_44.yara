rule Win_Trojan_Obfus_44
{
strings:
	$a0 = { 5554e9caedffffa0403540002c4ce932f2ffff8bf039deff25ee35400056ff15e438400083c410e914f8ffff59e871f2ffff8bf085f6e91fefffffe86f0100005056ff15e438400083c4102bd2e9c9f4ffff397c240c0f82cdfaffffff259f3540005f5e }

condition:
	$a0
}

        
