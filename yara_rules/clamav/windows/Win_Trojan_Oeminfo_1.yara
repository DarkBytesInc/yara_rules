rule Win_Trojan_Oeminfo_1
{
strings:
	$a0 = { 6f727420496e666f726d6174696f6e5d104c696e65313dceefe0f1edeef1f2fc21244c696e65323dc2e0f820eaeeeceffcfef2e5f020e1f3e4e5f220f3ede8f7f2eee6e5ed21624c696e65333dc1fbebe020ede0e9e4e5ede020eeefe0f1ede0ff20eef8e8e1eae02c20e220f1ebe5e4f1f2e2e8e820f7e5e3ee }

condition:
	$a0
}

        
