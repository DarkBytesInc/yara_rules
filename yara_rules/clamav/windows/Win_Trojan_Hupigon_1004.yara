rule Win_Trojan_Hupigon_1004
{
strings:
	$a0 = { 436e316a88ee1b8d1be7227ecd1b9c541ade89dfb46ddaed4c92f56be54d50bcf065d5bfb38dc0456352f1a069976bcab07ac8c804d6d47428ded963be8b707695312e9f29c9a9d7567be51bcbf6a1496da4124613 }

condition:
	$a0
}

        
