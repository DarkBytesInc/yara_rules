rule Win_Trojan_Bancos_1083
{
strings:
	$a0 = { f18d148e7c8f809c25c99b85cbdda9e9e0e31f27c9412623590c476f7e95c9ad64cb74f367b0be100b83ef704af3a2d5bf0360850de473e37ccdda8e9deedab073618419c98b0812d62d1f45213b7335ce0025f3bc }

condition:
	$a0
}

        
