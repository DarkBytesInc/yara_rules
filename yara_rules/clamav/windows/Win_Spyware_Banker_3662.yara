rule Win_Spyware_Banker_3662
{
strings:
	$a0 = { c67060049daf5dde50f944fdb680a95cda3a98daa315a25bb1b7afbb2d130d14868182b4b8ba9a4b56105f1e1a62c8610dfc1e1e3ff013b98d9f64ad44ff368adbe4c45fa77ba823d225e654490fc45661d6249dd4f58670d5592239bc20e5f04a3c6523c82a73531683cb179edf11ad4c3e3c7e7cf82f19433b6c95b527952d6f4f617581a04e03d27023c3 }

condition:
	$a0
}

        