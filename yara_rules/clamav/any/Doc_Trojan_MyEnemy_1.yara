rule Doc_Trojan_MyEnemy_1
{
strings:
	$a0 = { 6d726b203d2022e8f320e0e8e020e8e0e5f1e820eef2e2f0f920eee7eae720eee8f1f0e2e9c0202ec2 }
	$a1 = { 4d79456e656d792428332c203129203d204d79456e656d792428332c203129202b20225cc8e7e2f0e0f9e5ede8ff5c }

condition:
	$a0 and $a1
}

        
