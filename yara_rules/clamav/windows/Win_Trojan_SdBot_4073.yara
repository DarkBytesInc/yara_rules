rule Win_Trojan_SdBot_4073
{
strings:
	$a0 = { b46f84303fca84841a9f176adce99412d167ae0dd5cfcfcff09f523d2edf6cfdd3127406a1c2796f966822fe088c91bc85d676235956b375a5af26ced86c61986915bd41f362a793d38f8bd477cc6af140f0eac68b8b }

condition:
	$a0
}

        
