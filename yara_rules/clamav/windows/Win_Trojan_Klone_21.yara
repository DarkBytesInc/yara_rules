rule Win_Trojan_Klone_21
{
strings:
	$a0 = { 16cd6aa6182d24a200bb69c9d300f5ab31537b221a969739a7462c017902ea1e58c34bbd3a40c1b467c8d2e9312aac400785c14d16ba5b211bcd33930c52370829c24843c30344ce12b4d600ebdb63f641312f3047a06669610453c059edeef018350189b106e4db825675c9de446e02b92ce326e994a2803a48c6cdb1323150db095a7b548d3263724c5db851c50fe4c9c75580 }

condition:
	$a0
}

        