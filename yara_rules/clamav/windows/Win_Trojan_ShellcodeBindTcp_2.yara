rule Win_Trojan_ShellcodeBindTcp_2
{
strings:
	$a0 = { e856000000535556578b6c24188b453c8b54057801ea8b4a188b5a2001ebe332498b348b01ee31fffc31c0ac38e07407c1cf0d01c7ebf23b7c241475e18b5a2401eb668b0c4b8b5a1c01eb8b048b01e8eb0231c05f5e5d5bc208005e6a3059648b198b5b0c8b5b1c8b1b8b5b0853688e4e0eecffd689c781ec0001000057565389e5e82700000090010000b61918e7a41970e9e5498649a41a70c7a4ad2ee9d909f5adcbedfc3b5753325f3332005b8d4b2051ffd789df89c38d75146a07595153ff348fff55045989048ee2f22b2754ff37ff553031c05050505040504050ff552c89c7897d0ce8060000004f4c45333200ff550889c656681b06c80dff55046a026a00ffd0566880c8266eff550489c7e820000000f58a89f7c4ca3246a2ecda06e5111af242e94c30396ed840943ab913c40c9cd458508d75ec56506a016a0083c01050ffd78d4de0518b55ec8b028b4dec518b501cffd28d45f8508b4de08b118b45e0508b4a1cffd131c0508b55f88b028b4df8518b5024ffd231db5353680200[2]89e06a10508b7d0c57ff55245357ff5528535457ff552089c768434d440089e387fa31c08d7c24ac6a1559f3ab87fa83ec54c64424104466c744243c0101897c2448897c244c897c24508d442410545051515141514951515351ff75006872feb316ff5504ffd089e6ff750068add905ceff550489c36affff36ffd3ff750068[4]ff550431db53ffd0 }

condition:
	$a0
}

        