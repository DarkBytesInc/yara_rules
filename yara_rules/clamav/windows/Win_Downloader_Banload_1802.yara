rule Win_Downloader_Banload_1802
{
strings:
	$a0 = { e30d3d3cf2bec37bb74924b1fd76d6d9a93ff2e0e40ec2f59f8813bca92df9e6c566d13a2eab153842a2dcc7edba2a13d8c9298f513204c8d2f9d9322f2720db844ec2c141ea0a7e39818e5e9ee8788e9d8c485bed48da1549d74a99f3e2f7df597ef5d4 }

condition:
	$a0
}

        
