rule Win_Trojan_SdBot_1625
{
strings:
	$a0 = { 49b21904a8f5824f5f04e80232cc2f0e02036ccc565875522bb006be8c8a18d038c2b51630fb7b18b9ed5553f19d1cee2291e8d3650eaa722c81d866791cc1e6ea137d6384cd330362e9788d2792c4017a35686e0744c37b384e0e3a987c64c3d3fb6cdfb1f1754388b9c1e6c136cb43e77a182ee1e37245f245c12c170d719cdfe86cdc12b6e26314a0bb0e }

condition:
	$a0
}

        