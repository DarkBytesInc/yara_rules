rule Win_Trojan_SdBot_3835
{
strings:
	$a0 = { 39cb1b3559bde5c8fc1f9b864be0c6112058d17ac63941a7f757f41aedfb2afe642ed1edfa661db8079ed6eaa267f97e1d7cc91b79c71c94ba69a4cce1319b45ae89ee9332a2603c9fe51053c0f17b19afc8906792b51d1f39189e9af997e44e94ca }

condition:
	$a0
}

        
