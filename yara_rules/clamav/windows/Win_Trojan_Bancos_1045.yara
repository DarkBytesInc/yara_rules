rule Win_Trojan_Bancos_1045
{
strings:
	$a0 = { e1a0016d724316f7ac7853a44cde50fefcb5bdcf4430c49cde9449dce70d2643cef31a0d53e0e3f9286591898b04bf6d5646c64a42cd96f5acf5ae7691a163807cecda7c7b751ba3f02a9f1a3c6ddca88bf452c131a84e20 }

condition:
	$a0
}

        
