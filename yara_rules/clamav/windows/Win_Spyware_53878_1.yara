rule Win_Spyware_53878_1
{
strings:
	$a0 = { b88945c88d45b033ff50c745b033363054ff7508c745b47261792e897dbcc745c033363053 }

condition:
	$a0
}

        
