rule Win_Trojan_Agent_684
{
strings:
	$a0 = { c6028975086a10681412010056ff156410010083c40c85c0752883c620897508668b06663bc77411663d5c00740b663d4300740583c602ebe466393e0f84510100008b350810010066833b000f840a010000538b3d24100100ffd78945d48b450850ffd783c4088945d08b7dd48d7c3f026873617771576a01ffd68945cc6873617771576a01ffd68945e48b7dd08d7c3f0268736177 }

condition:
	$a0
}

        