rule Win_Downloader_Banload_1547
{
strings:
	$a0 = { 67e43107f0565a0ed5ce74f05c3ab4dd5283b3e1a4bc070f546149d8f2fc6b741372216eef2c60a887bd8c6c13dec6d39d583dd4868cc278476a59c0afd1c213d55d38174f8a65ecb181526c753c6512a6f1a7390bc4eacf460b }

condition:
	$a0
}

        
