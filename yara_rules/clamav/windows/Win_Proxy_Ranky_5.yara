rule Win_Proxy_Ranky_5
{
strings:
	$a0 = { dae08d894396c2b8982df0612954300f41a62dc38ffd4e369071d6296e081d9c9f533aadc674294d314995f64b4a692f68ec065c4b9f33787fe7655ee869de898c224a949460267ae1ceb98cc435d034661f68fa9c335d184fb6efedbc5505867e1e6e0ec5fe20809f7c40d458207f0f28875d88c4a4dd5623477bd85ce44eb0a8ba2642db30bfff3aa7c245e0468b09957b4602e00b }

condition:
	$a0
}

        