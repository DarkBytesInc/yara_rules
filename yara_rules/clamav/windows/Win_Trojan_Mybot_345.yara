rule Win_Trojan_Mybot_345
{
strings:
	$a0 = { 4f8f36f21258f6451fc44494d23b7bcd91cc1da27170c95c2087c13a53f53331ae8f4674d51fbfa6e4c42d2abae7ce467a1c695c765749684adc77a8535a95ade213fdc705e56d6899731b50529d3cc48191fdb46f0d8b4cc417cb46692119560fd223236c34ffc029c9c3ce23f2bde33e259ff96a3135657263cca42b387c889db401ae43e238c17881f7f1a95afec610e54ef1ef01 }

condition:
	$a0
}

        