rule Win_Spyware_4763_1
{
strings:
	$a0 = { 39626a6b6f0078786b787878786a74726a386a6f6b004d7367486f6f6b4f666600004d73 }

condition:
	$a0
}

        
