rule Win_Trojan_Tagort_2
{
strings:
	$a0 = { 74355d38313839315b3938[0-6]6972632e64616c2e6e6574736572766572[0-23]7461726761 }

condition:
	$a0
}

        
