rule Win_Trojan_Small_3632
{
strings:
	$a0 = { e20c2f0561788a42389dfd11389dfd11389dfd0ae429690bfc29650ba989adf5a437aff5a0872c80e989adf45c5ee7989bcd575ba798adc9f32eac42389dfd11389dfd0aec29690a60877dc12cdf1986221d2d057a }

condition:
	$a0
}

        
