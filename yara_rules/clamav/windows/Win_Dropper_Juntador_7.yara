rule Win_Dropper_Juntador_7
{
strings:
	$a0 = { 7d4492abefb63c9f1a867d9ae177ba14dec6caa007692d506f73b646064741595344f355e912d11a390edc046b736f1f2e95538b6b525b203ccfa23a9ea9e64fd7b4b6729016461e6e92f3e863dcbb5ecdd4f27d103c2e3c9fbe2ebd17aea7709cbd16b29232da2a1a4aca600d3129fe4f9f }

condition:
	$a0
}

        