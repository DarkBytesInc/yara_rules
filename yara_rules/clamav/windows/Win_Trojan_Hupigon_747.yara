rule Win_Trojan_Hupigon_747
{
strings:
	$a0 = { 95e9bd597b9b9228e9cbc9839cb2f4863035c716b287abe414bc91c0d02321a96d9188ff63a2e5816e3f6ad74e90f87f165871ea649b33dd2c32335accb1d29fd16b74655beccb8fa98c4f1e9253 }

condition:
	$a0
}

        
