rule Win_Trojan_SdBot_3991
{
strings:
	$a0 = { c6bfaee28060766e8751c04de384a705ef926f46af5aa8422dfd117d6ed35b5a3dabf2eada57792f596dffea06f8905fc0c26a8ce97cd974e32e9a417515c6d2696b49c80f0fa695db564afa7d0b8918f452d8de3cb5542be25a5e238dabe38b8a3caf521bfdd5428d5116ac52ded18938230dfdf0dbc02af4d9d692ae88d5da }

condition:
	$a0
}

        
