rule Win_Trojan_Small_5307
{
strings:
	$a0 = { 22fc8e11e314e58df63cdfe488fde1f60610cf8e73e400911efc115237fb03b236fba4962e3c8fed7c59eae7e152e6f61e0c8f8e88048ea3560ccf8e6efba4ca2e3c8f190f678ff84152f98e1d12e39e5efc134e932e1acb4e0ccf8e74fb6613df70b4e41dd40f0a4ffbeb0327528e659f60bf }

condition:
	$a0
}

        
