rule Win_Trojan_Delf_525
{
strings:
	$a0 = { e96b8ce9cdeb58464b687c08e6aee67019ba6f4d393972c49117f9a9c10d435202da1c632a4df2af94997c6993119531ce266ab540c60361d8362e7f16630d1493e118d39591e0a00748048fb09e56f3631ae4b6a832a97dac8c13b5fb0bd25ab7482848760dce07e7a4a236ea164f3c09f7309b4e8163a1f321e430f9 }

condition:
	$a0
}

        