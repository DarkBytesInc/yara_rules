rule Win_Downloader_288_1
{
strings:
	$a0 = { 89d8c772cb9eaa03e41de72507a15354716297c0859dbe16db80ef809c1c356456f8627105a3b5e92bf4cd43fa8731272b4875a0e9d5abe7addeaf731edaf0047625db49dfb785ddb39092c102ab }

condition:
	$a0
}

        
