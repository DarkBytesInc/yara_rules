rule Win_Trojan_Forbot_2
{
strings:
	$a0 = { 7a61fe836820de5cfb11a95b0c08e352fafb84c6f92a2324e2e2f7112409f5021138de1cc142f5c493fa2876af509120f2921920087c84524cfb8a715051430d08fb26af50911cf242191c082c845264f08a215050f3f9a5f008d6f8544718c4f2f6221810dc01914b4f48fc }

condition:
	$a0
}

        