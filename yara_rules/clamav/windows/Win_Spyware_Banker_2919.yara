rule Win_Spyware_Banker_2919
{
strings:
	$a0 = { 3429215f25ddcdbf1d3df5b4b9b154e2c9db81ff6d7858c3991d31a4ced91eb7a78bdf566fdcc630255e8c71212a58e9d9e370ce1ab2979aba2091e2c687960ffa38cdd1c72b2ce88b23fcfcdcaf832993b678b77fcfff3dd080cda62479ee80f6b20c44055cb652c82ad6a1c532 }

condition:
	$a0
}

        
