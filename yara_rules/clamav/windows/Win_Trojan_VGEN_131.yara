rule Win_Trojan_VGEN_131
{
strings:
	$a0 = { 2e9211fc8cd889865201488ed8a103003d00197303e912150e1f89868b028b9e1a03b44acd217303e9ff14b4488b9e }

condition:
	$a0
}

        
