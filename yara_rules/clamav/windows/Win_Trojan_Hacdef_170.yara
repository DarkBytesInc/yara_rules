rule Win_Trojan_Hacdef_170
{
strings:
	$a0 = { 7d0f9892ee23dd6e65e6e848cc7e9456497c440088ad587eeebfc695a5c929f002eba885283cad2ff35167e323d1ec590a91e0debbb9975bf679a976d622b484e8536b12d9a0188f6d5e9bb36b3bf68d35c42935642ae3e264ca5d5e2c3a165645980eafe80dcb0069e145200fe2869e506ccb20927b34296d980fde5474127be694789fda3573db19044bc6 }

condition:
	$a0
}

        