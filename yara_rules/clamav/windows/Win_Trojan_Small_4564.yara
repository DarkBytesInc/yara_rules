rule Win_Trojan_Small_4564
{
strings:
	$a0 = { 2992b5be54472dd814aaadd1277bed5832a52a385e8104670379dff7eaf572ca2e315eff4a01379270913506f677f4c15151bdf77872021ca7d99c07a11573ec9b9fc0dc8ece97ad96372b2e8875877ad0a9a64c616888b8a9edf37f0a849a1cd372a32739076c1c4630f6d0977b6ee7669c2a550b442f0037b1a33b2b2267c6516ef83104a733f8506ce960242dcc35 }

condition:
	$a0
}

        