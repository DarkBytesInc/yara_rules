rule Doc_Trojan_Smac_1
{
strings:
	$a0 = { 446179284e6f7729203d203220416e64204d6f6e7468284e6f7729203d2039205468656e204d7367426f782022d3c0d4b6b5c4d7a3b8a3202c20c9fac8d5bfecc0d6212121222c207662437269746963616c }

condition:
	$a0
}

        