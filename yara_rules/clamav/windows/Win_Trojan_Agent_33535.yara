rule Win_Trojan_Agent_33535
{
strings:
	$a0 = { ae9fcec4c22892fc500fd33e3fc76643b8be46460d94bde946be5a00e66d8a60495e1e9f3cb4f6ae7e35ebbf68c8f86d296e68bf8d4db33ae898c46a70fd0fef7b4291fade348f31cd502cdceb801baec18ab43b6cbd48a7743cd7738405a321a315ab0fdde409b5707b733c }

condition:
	$a0
}

        
