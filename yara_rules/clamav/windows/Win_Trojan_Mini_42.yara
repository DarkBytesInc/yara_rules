rule Win_Trojan_Mini_42
{
strings:
	$a0 = { 90b98000be8000bf7ffff3a48d0624028bc82d0001a3fa00030e2202890ef80003c8890ef6008bc88d3600018b3ef800f3a4b003a20101f98d161b02b44eb9 }

condition:
	$a0
}

        
