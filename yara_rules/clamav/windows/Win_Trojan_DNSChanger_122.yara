rule Win_Trojan_DNSChanger_122
{
strings:
	$a0 = { bf64dd69280fed646f9df0a9e9b9169dcdf9011c151616b06d29b09cc0169dcde501fd1616166d29b09df2646f4df2a9e9b9169dcdf9017b161616b06d29b09dec83e8b1b72a6a2116b72abc6205b86a8c15e9bf629ce16c1f9d99bf16fcadf8a9e96c29 }

condition:
	$a0
}

        
