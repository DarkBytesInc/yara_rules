rule Win_Trojan_VCC_30
{
strings:
	$a0 = { b440b9e6028d960600cd21e80500b43ecd21c38db61100b9b602803400464975f9c3 }

condition:
	$a0
}

        
