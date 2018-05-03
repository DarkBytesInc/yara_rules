rule Win_Tool_AnsiBomb_5
{
strings:
	$a0 = { 7476e99600b8d70250b8220050b8ca0250b8220050b8c40250b81b0050b8b7025056e88d05 }

condition:
	$a0
}

        
