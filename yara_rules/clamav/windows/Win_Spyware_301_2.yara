rule Win_Spyware_301_2
{
strings:
	$a0 = { 6cf831c7c27516820f7d5f5400fd5cdebe4e5dd04a2e42a7990e4403badf5a7a3e5c3ec2f41f232ecb94aa2b9abed1993537b17cff92d932ce7fa1a8daa4bc9bf9c83cfd40cb7ec1614de3fec03155ed5453da85450f0f014039109609fb9b }

condition:
	$a0
}

        
