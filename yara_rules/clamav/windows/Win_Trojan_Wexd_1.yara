rule Win_Trojan_Wexd_1
{
strings:
	$a0 = { 4ade123cc623b1f9cc5267ebb8be9194d2a0e37252a2e3b9de096a264040d4a2b7c279cc47a8478ae61c77ed70c5ba24f3903b6af942d4521b06e6be484aadcae4895948f41dbd8d97a2d690062efd3e9e1f8d93222c2a7d5a2e89104ca2bb79 }

condition:
	$a0
}

        
