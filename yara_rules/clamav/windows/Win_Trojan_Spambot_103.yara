rule Win_Trojan_Spambot_103
{
strings:
	$a0 = { 42de60702ea9ff4001ed1b99ffffffff993c9a17348cb4c640f2ded798270b0a36fb4ae4254dd354679a35a77ef1bce4ffffffffe6cd32e9813543dc3f1670af76f64f75fd5a1d01a53ecafbfa3caa8b0fadfe2949faffbf2cc94ae24c9640629b031e1c7f591e92a6a2ffffff7f }

condition:
	$a0
}

        
