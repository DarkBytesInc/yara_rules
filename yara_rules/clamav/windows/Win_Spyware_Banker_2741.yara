rule Win_Spyware_Banker_2741
{
strings:
	$a0 = { 19ad5c35c2580f83ccb25684ed5b72fa9ad2b82d27aa7b04142484c34e125ec551e2c3206a8c1bb88f25420832c568ccf20a27928b7744191505cd42682d6bc3fdd2cd7402b629a30a69fbfbb177 }

condition:
	$a0
}

        
