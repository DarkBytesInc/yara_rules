rule Win_Downloader_Small_4589
{
strings:
	$a0 = { 8908c81c7c4ec8284110a180510608e40d44c35be8fb01189aa1103385c006750e68f011812a15842c86e8cb3922680cea08df0bdbc11f7b2ec890244055948d45e650c8c6209e51ff199c521e90ffc14da0f321808c851468044e1d11b290803e328975018c803e220f85a9982f461b8a060384c074043c22d3f27f2ff35e090f0a3c2077140701ebf0c745 }

condition:
	$a0
}

        