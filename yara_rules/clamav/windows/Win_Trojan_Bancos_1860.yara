rule Win_Trojan_Bancos_1860
{
strings:
	$a0 = { 3531bdb145f86e8107ba993f304e81edaf9fb3b873dbf8b4adc163601e1f3b0ed54845079462c5cb082814081088d8998c0f40ea555aa3416fb01a0c9e007b8ced356dd46a56 }

condition:
	$a0
}

        
