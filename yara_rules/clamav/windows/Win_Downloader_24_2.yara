rule Win_Downloader_24_2
{
strings:
	$a0 = { be769ec1f82a81c5e6be01daf2eaeadf3f3beb7d70307974be3b804c3874c669e7607974fdd691b5e76e41fd2cea90fbc8eb8075a6ef8175e7548b022dcfeb7537d36187e7ead7026dc77e74e75581c5cfbc9375e7f936baf2edc56952edd0022dcfd15d7efd80756aafa5026dc77e74e742d1022dcfd174 }

condition:
	$a0
}

        
