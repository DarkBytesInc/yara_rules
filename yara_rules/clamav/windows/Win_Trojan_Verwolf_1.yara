rule Win_Trojan_Verwolf_1
{
strings:
	$a0 = { 41f85bfa29edbc65002e81465e81043681465a81012e814660fe832ec7465c6a003681466889362e816e62360f2e }

condition:
	$a0
}

        
