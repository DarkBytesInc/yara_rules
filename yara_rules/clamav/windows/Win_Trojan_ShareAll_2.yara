rule Win_Trojan_ShareAll_2
{
strings:
	$a0 = { 37b8f3244203179b3a83000000c0000000000b000000013750726f6a6563743100105e436c61737365730010c7436f6e7374730000c753797374656d000081537973496e6974001051547970496e666f0010025379735574696c73000c4b57696e646f77730010734163 }

condition:
	$a0
}

        