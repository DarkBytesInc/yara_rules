rule Win_Trojan_Mybot_8452
{
strings:
	$a0 = { ecd6e7a0c77f4dbe383982ac7516cf5ff0b46dad36891f9df64d296fd0e3f4e7aed48e27765aa9f940ec28cc97700209f7de65772100afc87fddbef6932bdc8a770227e1822616c71deecd2ad5ca8e25caa04085f7 }

condition:
	$a0
}

        
