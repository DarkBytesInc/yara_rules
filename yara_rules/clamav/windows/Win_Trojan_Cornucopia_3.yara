rule Win_Trojan_Cornucopia_3
{
strings:
	$a0 = { ba90c53bc473678bc42d440325f0ff8bf8b9a200be7c01fcf3a58bd8b104d3eb8cd903d95333db53cb0e01504b }

condition:
	$a0
}

        
