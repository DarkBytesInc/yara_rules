rule Win_Trojan_SdBot_4
{
strings:
	$a0 = { 74e84b0d0cd5bd7b33257382b215be6ab76d495243655e3290a9d1357ad101615dd36575744cc5e6c4ad1f3f25b8736b630add268308202f63c02b40651b0b0c }

condition:
	$a0
}

        
