rule Win_Trojan_Small_897
{
strings:
	$a0 = { 746f2e6461696c792d776561746865722e636f6d7c2f6175746f2f776561746865725f666f7265636173742e6173707c4461 }
	$a1 = { 040a8a043088040a4283fa247ef083c4fc68406240006820614000680060400068a06340006860634000538d8500fcffff50 }

condition:
	$a0 and $a1
}

        