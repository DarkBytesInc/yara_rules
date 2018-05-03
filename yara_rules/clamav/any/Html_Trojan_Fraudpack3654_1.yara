rule Html_Trojan_Fraudpack3654_1
{
strings:
	$a0 = { 5531c08bec81ecd4020000575653ff15[0-3]006a006a006a006a006a006a006a006a006a006a00ff }

condition:
	$a0
}

        
