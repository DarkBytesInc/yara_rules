rule Win_Trojan_Bancos_917
{
strings:
	$a0 = { 3cf3044480856beeb36f8160a813ecec5a25bf2af167f6d99faf6799b2d87153c1eea812d5efbf77cf8df411e389744f1085a9f98352227a769b6d0c6e97bec8a25e3ffe8a5eece61ebf2ccd11853adfe852522aa1 }

condition:
	$a0
}

        
