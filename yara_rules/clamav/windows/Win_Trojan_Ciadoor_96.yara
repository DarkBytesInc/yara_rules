rule Win_Trojan_Ciadoor_96
{
strings:
	$a0 = { 63d4c88237df3b8073db4b7b63d27b99008de0ef8559e7a2b7d06f7a73ccab68bcb871456f0757195cc929fbb5e8e28fafb83f6c4bdf5f093e3ee05023e9fb76ab31042d61e2afc54056a50d12c65f9d3f9e381b87c20374af1e5c6c27520073f76575a1d18dcf87c87ccee13bb32e58d5e9d7826bced30583eacb3b44e2974b7f7aa7ecee5ab25144f9b822 }

condition:
	$a0
}

        