rule Win_Trojan_Hupigon_572
{
strings:
	$a0 = { 3e5009903a273d7953ac0cc1e72f17bad6b101f4b5bff419e6f3d6b76912cd511b9ebdac92368d77a1768feefda82627f8160234a22c8425314decd56db6768a751ab156ab8815a312d6ec620137ca83f4f01343a9d28eadd947a12a953cc979c8caabf8fd74e393a24b54efc9dc60e7859ce6aec6cd9bbf848c234f31056e1d94f63d68a4fa638d0c3c347a90c5268d546a40b1 }

condition:
	$a0
}

        