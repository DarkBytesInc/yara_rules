rule Win_Spyware_Banker_2625
{
strings:
	$a0 = { 44dc4d802a6ce59cd295464dd0f7731fd3ee090bdb683df9a1e2e00c39a56823c2d1e73d83b81548b449a052555cf3aa4626f731927df3c6030ac58990add4e4af4711be5d23f02e60a94ad86088d066452fd8f8ec0aaf08ffc66e0be18ac88ddde6 }

condition:
	$a0
}

        
