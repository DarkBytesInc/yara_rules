rule Win_Trojan_Flux_5
{
strings:
	$a0 = { 448b023bc875022bc95051ff7330ff531859585bc20400558bec83c4fc538bda2bc96a065a648b4130384b0275034a8910881033430450ff750cff7508ff155010400085c0746750ff7330ff5310ff7510ff530885c00f9445ff5874342bc9384b02648b5130507403c1e80240c1e0030342448b4d10334b0489 }

condition:
	$a0
}

        