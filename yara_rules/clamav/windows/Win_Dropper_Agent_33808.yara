rule Win_Dropper_Agent_33808
{
strings:
	$a0 = { 833d7cb7400000743c833d80b74000007433833d84b7400000742ab858b84000ba6c754000e8debdffffa174b740008903b858b84000ba788e4000e8c8bdffffe8fbd6ffff }

condition:
	$a0
}

        
