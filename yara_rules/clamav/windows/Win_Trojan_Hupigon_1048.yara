rule Win_Trojan_Hupigon_1048
{
strings:
	$a0 = { 600a1062a0828c8fd10881438044e7d921c20eeed6adb9dcc6ee77b9a7e1dfc077b99dc816f77206eddef01dbbd816abc8b7ab05ed5e48ad202dd7202d720975c906ae41b75ce056dce01adc920a6406eb902f5cc83bb772037bdc837d322b7b996efe1bffffffb7dff7f7f7cf9ce79e7cf3cf9e79e739fbff7bff0454c0e229cc569b4da37ab26fa3c77cff }

condition:
	$a0
}

        