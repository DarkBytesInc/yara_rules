rule Win_Worm_Kickin_1
{
strings:
	$a0 = { 48b7e390abe1fef8fd747b44654e17ca7c2cfedfa9e7dc3732fe84d753f3d1756ab4fc379b6bf19b0836a0538dd575ef41149fd01d09409558cc30cd6932d276815c070799f6baa980c770f8b820babd }

condition:
	$a0
}

        
