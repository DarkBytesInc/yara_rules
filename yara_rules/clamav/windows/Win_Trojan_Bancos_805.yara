rule Win_Trojan_Bancos_805
{
strings:
	$a0 = { ea5da9b780d9fa8c0a7c7d9caf0db7c3a07357b85fb726f64b46bf5f2d56960ae50ea009164889391c35bba17ebe3696558e4e73f72ee6876f48929a0564dd17da8d3a5c942f5e819b088d9d94fd110ff748 }

condition:
	$a0
}

        
