rule Win_Trojan_Qooloc_4
{
strings:
	$a0 = { 2641d0d299c9844179e9838ee2c6f5c89230f28bdc853af4ad70f6d1218d59df9192b394cad07676683f4d622549945777a135f0e6d5220b6c71ca3c363544bce86d283c73f634abbfdba1c3fca546519b064655bf88e51979eb0beb251158f7c093d7050a153b53b3c898b714499a0b77f83b3a8866543c7efd9442ca9b447793fbe1d9e88fdd9e6c43bff30dc40ffef6208cb9ad }

condition:
	$a0
}

        