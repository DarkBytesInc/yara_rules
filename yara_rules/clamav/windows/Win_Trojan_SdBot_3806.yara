rule Win_Trojan_SdBot_3806
{
strings:
	$a0 = { 18b2a73ad0d2579ae82a44be4c25e4736d92e3edef42dce1b9fafc81c40e918bb0010b0d607afc825b1aa7a36421232527deb1922f31331eef033c3e99ab047a4a4a4c4d0076c79a5842b1975f61e72a74f5b19a59a4c976780501c27f8183853c0f }

condition:
	$a0
}

        