rule Win_Tool_ICMP_1
{
strings:
	$a0 = { fa4200f8de410038000c6576696c70696e67756e697400008d4000558bec6a005356578bd833c05568b6fc420064ff }

condition:
	$a0
}

        
