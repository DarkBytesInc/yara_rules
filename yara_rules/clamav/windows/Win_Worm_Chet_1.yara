rule Win_Worm_Chet_1
{
strings:
	$a0 = { 688c6a4000e899f1ffff85c0590f84be00000068806a4000e886f1ffff85c0590f84ab000000833db4824000007407686c6a4000eb05 }

condition:
	$a0
}

        