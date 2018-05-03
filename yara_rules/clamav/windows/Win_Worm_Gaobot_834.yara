rule Win_Worm_Gaobot_834
{
strings:
	$a0 = { 2f5ee5ff22d778ee2ba6085d070d21e182da50303ea1312a11ccdf7990b0900cd3e54f3851c05d552f1fd0c6be50ad8733d15746e7ae8604976bdb885b2991ceb7a0aeb4cc8a8261f7bc3fcf90df2b96dc085ae44904cc4eb8145a7e38fcfa6d431109ed73d13a0fe2afd0fb2b }

condition:
	$a0
}

        
