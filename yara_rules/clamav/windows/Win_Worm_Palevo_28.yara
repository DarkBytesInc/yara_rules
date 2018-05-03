rule Win_Worm_Palevo_28
{
strings:
	$a0 = { b89c8d4000ba54644000e88ddfffffb8ac8d4000ba68644000e87edfffff8d55e8b87c644000e8d9f9ffff8b45e88d4dec8b159c8d4000e834fbffff8b55ecb88c8d4000e853dfffff8d55e0b898644000e8aef9ffff8b45e08d4de48b159c8d4000e809fbffff8b55e4b8908d4000 }

condition:
	$a0
}

        
