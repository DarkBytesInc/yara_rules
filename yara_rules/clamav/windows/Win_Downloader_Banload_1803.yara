rule Win_Downloader_Banload_1803
{
strings:
	$a0 = { 2df9e6c566d13a2eab153842a2dcc7edba2a13d8c9298f513204c8d2f9d9322f2720db844ec2c141ea0a7e39818e5e9ee8788e9d8c485bed48da1549d74a99f3e2f7df597ef5d4fa5fe1c5dfdf14f7b286e915c9106aeb2b835723e157cace8dd5b97e58 }

condition:
	$a0
}

        
