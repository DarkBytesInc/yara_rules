rule Unix_Trojan_MSShellcode_99
{
strings:
	$a0 = { 7ffffa783ba001ff97e1fffc7c3c0b783b7dfe119761fffc7c3a0b78fb41fff9fb81fff9fbe1fff93bff01ff3bfffe02382101ff3821fe09fbe1fff97c240b78 }

condition:
	$a0
}

        
