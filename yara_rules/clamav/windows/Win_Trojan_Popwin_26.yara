rule Win_Trojan_Popwin_26
{
strings:
	$a0 = { 56b794dfde67941be3d06a8a25fa2a6a47358ccfcdbe064378ccdb0a579e78f57f8fba2d6fa35ecccb5339555881651cc8ce3d22945257b33999b435588c16356ad1d995ae39506feacf410c3e94b9efbc831c59af2f3f2cb8701d55c06b7c9d }

condition:
	$a0
}

        
