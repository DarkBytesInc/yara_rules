rule Win_Worm_Gaobot_777
{
strings:
	$a0 = { 3afdb5f0f5acb1a6e4a6a4350bd7043885716490e7e3596d5b94aa9dd02a3ef6588a5edcc21967ddb3e5695dc7e55194b7d5b90e77d2ba1a3b1cdc7d7fcf1ce026068334b828f477cfd34916300e179eb9cc2fa5993d3b0c1f26fa24010dc8ffaea757b5364b173d5815a016372304cc }

condition:
	$a0
}

        