rule Win_Spyware_Banker_2654
{
strings:
	$a0 = { b6db8f4ace8de3a684b9ce0d6e84b9bf2441aae74ea8b6cc09e63f28c673f07c84adefbc5ebea1b1aff1be2ec06689758bc726f50ce0ac9972a81b96c926c839e15fb82610cc30489507188b0882eeaea2f3bf23968c467cd0a78e0adbc2daf59eda }

condition:
	$a0
}

        
