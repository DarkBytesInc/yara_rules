rule Win_Trojan_Pakes_462
{
strings:
	$a0 = { c983db8f4d3566538005716f5699811649e6b110756af6a6497eb6972c7c7c21a2cfbb62e29f43f446757b6cd675a4795d3e764c03217d66a62bca6d87d07e0caa73bf42567e4f1765738eb8c7416d49602e7af85ce0767e091ebbda729ff1bfd1705790c7253dbba6cb61917302df1ec938d23f3ff7a4c2e2fb4357457d43443713d6053879b76c0ff2ea6f }

condition:
	$a0
}

        