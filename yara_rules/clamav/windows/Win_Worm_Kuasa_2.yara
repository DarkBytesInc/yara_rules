rule Win_Worm_Kuasa_2
{
strings:
	$a0 = { 466f722045616368204164647265737320496e20616464726573736573 }
	$a1 = { 746163686d656e742e4164642022633a5c6c65656d652e76627322 }

condition:
	$a0 and $a1
}

        