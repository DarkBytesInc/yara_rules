rule Win_Worm_Stration_406
{
strings:
	$a0 = { 658ba9c88ac2eb59c0c9ddbe1aae7be47b587c79c8ba52530f836da2af7dc0eaeaa9ec4ca282eef578a2aca37a7c41082d5e5c0e7b6a34a1ef967bee9693c75de0b91342ccdfa641c2f8ac2667b8b60c8d9390fae113245c7043f3f7e3510e89 }

condition:
	$a0
}

        
