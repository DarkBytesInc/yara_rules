rule Win_Trojan_SdBot_1611
{
strings:
	$a0 = { 7961ba15a75dcb133639faf0d96d02050a682a4ffa4afa566f72eaeeb967397f369dedaa9fa6befc390b95626179513349a67e2a354d6a5f21f75a8211994a3506c52183d0b5ca93a5a5bc31f9caaace836dd5 }

condition:
	$a0
}

        
