rule Win_Trojan_SdBot_3740
{
strings:
	$a0 = { 338babaac3ead5e094b83ea25870eba3884ef7e4f076e04d8e46336d8fad8a8a5bb7fe8829ef65aa36f069d66afbfcaaa4fe3b9de449441de9cfda3c31acc231cac2ef245077be5ae7cd58cf4646a009f1dcd0fbc9078f9d96eecb109a5a256fd03603d87a47a73ed36e5beae492 }

condition:
	$a0
}

        
