rule Win_Downloader_Agent_719
{
strings:
	$a0 = { cedc12b3dbb347ed7200c66e82fb05205f9cbc7f0fb7a26066d8cb0a4ff83ece8f77ce404737404a4f796b03de79c405261de68dfeda8a0e683dcbbf34f16d4ddecf4597d41e11b502a61036f0c5702dac99d84d6cb26546a768a8ed308d49235859fac6c3e132cd92e2bde867520cd751f9342565f41e639bdb014614e660616380c9744e45a24c0ba0a95642051716a54b2574c295 }

condition:
	$a0
}

        