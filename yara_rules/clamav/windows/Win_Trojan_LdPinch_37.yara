rule Win_Trojan_LdPinch_37
{
strings:
	$a0 = { 34540f13c80e8c24c09454c2af6a30627b63bd7aa4887023749c3831157763a66064137e726d703978feb67cbf43f178ca487da9bc7ebd1d2bc419a06d04c7d6d9458a470bd0e2e711d30275bda74454e6fc572658343989848f41a9eaca3490a58d8c78a38405153e5ef3710ac28c3c2309315694a59fa7c5d6f1a9cddb7075da2ae581d754148572a8e48a37b174fb9e7f312d7d14 }

condition:
	$a0
}

        