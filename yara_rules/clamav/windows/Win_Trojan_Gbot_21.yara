rule Win_Trojan_Gbot_21
{
strings:
	$a0 = { 558bec81ec600400006a006a006a02f8e84b000000fc83e8044003d10fafc2906a065a25ff000000f9663dac00f8f274746a00ff15????41008bcd3c57753826 }

condition:
	$a0
}

        
