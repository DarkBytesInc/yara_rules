rule Win_Trojan_DrDemon_4
{
strings:
	$a0 = { c08ed88b1e130483eb0a891e1304b106d3e38ec326c60600005a26c7060100000026c70603004002438ec333dbb809 }

condition:
	$a0
}

        
