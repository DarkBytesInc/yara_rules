rule Win_Trojan_Bancos_1021
{
strings:
	$a0 = { 8dad9a993a02e73b417ee8ec6b44cc9bbb6f0a21985762458a301a0a72b8aa938f16384d42371a5f1456903825267d9bf6717a2726aecb506fa6e091f4b3e56d }

condition:
	$a0
}

        
