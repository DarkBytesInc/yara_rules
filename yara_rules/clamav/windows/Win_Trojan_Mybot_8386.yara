rule Win_Trojan_Mybot_8386
{
strings:
	$a0 = { 0736fbe47ebfdf9b91c6aa0ffc01fd62afe5a0c848db0ec68d982a5cf51d156965c26d5d80fcff71809f40830151b48e45afae7eb3242b61c4bc27cfcf412cb816adeffa4829f920d05b926b2d24319ce33ae440cf }

condition:
	$a0
}

        
