rule Win_Trojan_Hupigon_1692
{
strings:
	$a0 = { de7d4c893e752be7d574d5c10f65ec2f3227ed24bb5e12296097d681634a3b19149bfaff0381070cacb75c58584750e63122976c4abadfee65b3475dcf2ce2c6d2cbe0fc50313d7c621924d870d40e5e3b106c4e4be2185568f4dc06cceee241b810 }

condition:
	$a0
}

        