rule Win_Trojan_Agent_32727
{
strings:
	$a0 = { 0b231f667a27d4e466a224cabdca714c824ddd53ab6bca45898fdcd4cf5766a7471f063a27252484a900ba74965378d3273fe7612bc22686e75841fe }

condition:
	$a0
}

        
