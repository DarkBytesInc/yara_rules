rule Win_Trojan_Small_3664
{
strings:
	$a0 = { f318461a272ebe3593cc535c35ee120c1ddafc6e4653519916bb12bbe705706159b06a0cac43776ce3f6526fc290a1f96bf82212b2e9c1dbf92e43d3ae6e41dadf1d9504a1782b3a5a4025bb74737e8e2eba4c290f873cfcfe2f }

condition:
	$a0
}

        
