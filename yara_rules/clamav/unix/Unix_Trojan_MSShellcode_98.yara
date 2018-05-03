rule Unix_Trojan_MSShellcode_98
{
strings:
	$a0 = { 7ffffa783ba001ff3b9dfe023b7dfe03fbe1fff9fb81fff9fb61fff97c240b78387dfe02381dfe6744ffff027c7a1b783b3dfe113ee00a0762f74dba3ac0115c }

condition:
	$a0
}

        
