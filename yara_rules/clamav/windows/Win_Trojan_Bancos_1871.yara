rule Win_Trojan_Bancos_1871
{
strings:
	$a0 = { e8366b2a73d6dd038b935b77703b862e367a5bfd2e2e02769cbf90162b830101310236cf0a4ee27973ee58c4d6a2043e914f05d7e6d6ff178ec56114177f4e31f2d5dd53d6cf }

condition:
	$a0
}

        
