rule Win_Trojan_Agent_32912
{
strings:
	$a0 = { 5822f7fbd7e484c8866686cbf1639116df59cb6e8ad9ad239c67f962d7c3d3fefe6c1f7f3afb2983d3fa263e0dae555bd287756d32b249411e2943fde584b72b272137b39ec291610821ad0ed6f1 }

condition:
	$a0
}

        
