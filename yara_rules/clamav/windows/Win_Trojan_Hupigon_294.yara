rule Win_Trojan_Hupigon_294
{
strings:
	$a0 = { 241a56fa3bc111d0ed95e3a30f586ec24b27155fed689dc89d4b46ec71eb34174ef64c2809d58afc0c0bab3086632687d0cff6045ddc985e1eaafdef6756dbb27c173cdbca4e1f93bdad5fd289fbfdd6f066614f42c1f45f733de2a2aec45a9cadff7e453a56767fae }

condition:
	$a0
}

        
