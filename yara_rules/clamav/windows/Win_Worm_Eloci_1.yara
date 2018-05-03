rule Win_Worm_Eloci_1
{
strings:
	$a0 = { 63cb47b3e111d947a865cedef7f5c6c80b09333170e758f36eae6ed550f115d2556d59620d6e1c785532d4ad579c46ae46b694caab8abd6609753fd96ba0caff114ec103c60b6b2f2116f1420a58ab29 }

condition:
	$a0
}

        
