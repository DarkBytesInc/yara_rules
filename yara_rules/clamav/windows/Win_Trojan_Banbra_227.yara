rule Win_Trojan_Banbra_227
{
strings:
	$a0 = { c3ff2f7c09cfdfacca96e3aeff57e8b8f705c6ed6bf3edc9aa837dc9c4c74009310a9b855ff85b2101acdf8b84f89fd00b1b8973c327087cbbf0d9ff06ceb425d81c6ff07fdf17cc0e40f14c1d22d7340dc3f20b0046cdd483b3471affffd7711d701d19b12f23bb442bc3561b9934bfd9ff7f8b5b59a3b505dee6e6c4bfbfa3 }

condition:
	$a0
}

        
