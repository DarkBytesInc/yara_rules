rule Win_Trojan_VGEN_398
{
strings:
	$a0 = { b8a154cd213d660674401e59498ec18b16020081ea1a0026812e03001a008916020083ea108ec2bf0001b9830189fe }

condition:
	$a0
}

        
