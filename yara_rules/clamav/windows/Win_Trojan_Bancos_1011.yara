rule Win_Trojan_Bancos_1011
{
strings:
	$a0 = { 49550313b7420dde9722736c80b2173c6e2ee5a2accedea0654c0dc16d57e738967a7eb2a066da38238e24d0d38a63319a34f84ee848bc6a8e401e2fb0f2be185aba866db7659b2a3a8ec3b933219a47d2dec3e4acd890ef }

condition:
	$a0
}

        
