rule Win_Trojan_OptixPro_21
{
strings:
	$a0 = { 0c5fbf8db8450e3166f9873243d305afa57749d918c851aeebdab76025abb0beca7d5335e67584a6e1c84e77693a36a192e88553977517754ee5def05e22d2ccb4a6621203f47bfca8ce37b0b09fd5c01497cdfda5f825079b49ae109808454e1c266230ba473c541d31f73ecf330fcfcf529ae40ad7870ba792e1 }

condition:
	$a0
}

        