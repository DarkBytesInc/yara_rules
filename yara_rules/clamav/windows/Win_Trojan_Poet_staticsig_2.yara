rule Win_Trojan_Poet_staticsig_2
{
strings:
	$a0 = { ea49a2928754b10693c59887549d0693c5018754d106941185988754a10693b5048758110693b501 }

condition:
	$a0
}

        
