rule Win_Trojan_Bifrose_480
{
strings:
	$a0 = { d0d77f5aad91e2d0219378f0bcc3780e4989b41a69f630c441574abb6618cf36ff523118cc104c4e21bac6f4bc8074e2f8920e00da19faaf45072a997e2666eae3cf7c30ac167a40f3a8f3a84177dd03611b6d600808f6d2cb04 }

condition:
	$a0
}

        