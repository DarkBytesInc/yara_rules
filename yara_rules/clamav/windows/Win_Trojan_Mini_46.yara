rule Win_Trojan_Mini_46
{
strings:
	$a0 = { 8000be8000bf7ffff3a48d0676028bc82d0001a3fa00030e7402890ef80003c8890ef6008bc88d3600018b3ef800f3a4b003a20101b42acd218916f200 }

condition:
	$a0
}

        
