rule Win_Trojan_Mini_43
{
strings:
	$a0 = { 90b98000be8000bf7ffff3a4b866028bc82d0001a3fa00030e6402890ef80003c8890ef6008bc8be00018b3ef800f3a4b003a20101b42acd218916f200890e }

condition:
	$a0
}

        
