rule Win_Trojan_Agent_33386
{
strings:
	$a0 = { 14cafce520e677e915e90c079d816a852d0440d3d56b245c8d2a03dc410a8e2b2bb8dafd7d6c5af3b19196c66a95efd9a3530614f42730bd9332a9db0fea1d1f15f9b904735b2e95ffe6fa631b425fa53fccd00702bce731345a8a4e }

condition:
	$a0
}

        
