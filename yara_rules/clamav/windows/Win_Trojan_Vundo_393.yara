rule Win_Trojan_Vundo_393
{
strings:
	$a0 = { eb0eb625da90feb46ad88efcdcbc557c60e80b0000004b132b430b23134b1b033b5883c008eb3edceaeb52e09e8472c866ac7a30ae540218767c0a80be249268864c9ad0cef422b8961c2a20dec4b208a6ecba70ee944258b6bc4ac0fe64d2a8c68cda10 }

condition:
	$a0
}

        
