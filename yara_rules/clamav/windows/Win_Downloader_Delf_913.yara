rule Win_Downloader_Delf_913
{
strings:
	$a0 = { c0467ef751d215ccf884c9485c2b5bf8585b6efc858b2990c54d20ba147e99dd0878f1326be2fc6d93941144a1b5afb2f778cca34e671e8bf7ad2c6f1f45cd4fece4d25f7efc29aa9de22cabfb33ad0a29eb8a92984e3ff9b931738a71863687f8b6019a }

condition:
	$a0
}

        
