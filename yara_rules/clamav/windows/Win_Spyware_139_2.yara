rule Win_Spyware_139_2
{
strings:
	$a0 = { 4c5fbc2aef2649ed25fac77ecdd0d3021a3459d77fdd4cd15efdbfdb51620a05c16ece40e3dfbfa0a2c9bd57b7cbf39f0a7015ec5460978d05f8c4bb05c3b471fa9680714f7b2efc3866475d57c9b5dac82b56886f266a690bc1ee263713 }

condition:
	$a0
}

        
