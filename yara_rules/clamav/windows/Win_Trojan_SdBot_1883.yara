rule Win_Trojan_SdBot_1883
{
strings:
	$a0 = { 5c921b674518c8d58ab8bf03708da91f7ef758f82a93e24c10491db78cf07c1a67cc9aedd6d215825f4d7f10e1375af861c391c8ee61ba65ffc1a043e2eae2e1a59aeefc4beaef96fa54de31ff7df6d6aa8d0b25f39035e2f252998bda33d560ca99456fb9ba4150af778b4aef72 }

condition:
	$a0
}

        
