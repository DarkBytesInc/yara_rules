rule Win_Trojan_Rukap_57
{
strings:
	$a0 = { c1e379ecf973c18804c79809b41fcc098d7424b6172d9229608bb4493faef9c19b21394679f5a52261c3d200be78fac3b56ddef06cb26b334d4fdf870f39f3250c1d584d74389fb4 }

condition:
	$a0
}

        
