rule Win_Trojan_Small_3626
{
strings:
	$a0 = { ccd1ea79ccd1ea79ccd1ea7488655e73906562733dc51a5d487b1c5d44cb9bea7cc51a5e3095e4026f0195c34bd61a3197641bacccd1ea79ccd1ea7480655e7404cc6a29c013cff0c5519a6d0eb753739065623177 }

condition:
	$a0
}

        
