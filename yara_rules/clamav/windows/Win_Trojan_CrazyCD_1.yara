rule Win_Trojan_CrazyCD_1
{
strings:
	$a0 = { e9f7e0f1204372617a79434420e1f3e4e5f220f3e4e0ebe5ed20e8e720f1e8f1f2e5ecfb20210a0a2020c5f1ebe820fdf2e020eff0eee3f0e0ecece020c2e0f120f0e0e7e2e5f1e5ebe8ebe020e8ebe8200ac2e0f120e7e0e8edf2e5f0e5f1eee2e0ebe820e5e520e8f1f5eee4ed }

condition:
	$a0
}

        
