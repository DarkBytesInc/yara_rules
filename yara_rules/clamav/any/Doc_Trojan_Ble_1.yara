rule Doc_Trojan_Ble_1
{
strings:
	$a0 = { 537461747573426172203d2022cfeee4e3eef2eee2eae020e7e0e2e5f0f8e5ede02e20ceeff2e8ece8e7e0f6e8ff3a2022202b2053747224284f7074696d6129202b20222522 }

condition:
	$a0
}

        
