rule Win_Trojan_Agent_543
{
strings:
	$a0 = { fcffff50686c7500108d45d050e8d9f5ffff56ffd78bf8478d043f83c00383e0fce8520f00008bc4ff75f8575650e845c1ffff807d10008d4dd074046a01eb026a0050e88cfeffff8d4dd08bf0e8f9f2ffff8bc68da5acf8ffff8b4dfc334d04e8380300005f5e5bc9c3e87ce9ffff0fb7c050e8a6eaff }

condition:
	$a0
}

        
