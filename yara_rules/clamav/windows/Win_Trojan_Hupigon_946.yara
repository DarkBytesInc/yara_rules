rule Win_Trojan_Hupigon_946
{
strings:
	$a0 = { 1f8431293087e6a2fcb4234f2e42aedc992db69de69c50226043fdcc5d765c22bca47d301e05def79ef647b80f7cebfcea1a05ac3344231488f84f3383070a367aec84859d9ca626236a9ff641df90f57893fc4893a780f7459979e0df36ee38a474606465fe42e0d710862af000efa2bae0768c2c463b823a05aaf9030092e2 }

condition:
	$a0
}

        