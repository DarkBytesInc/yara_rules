rule Win_Trojan_Rukap_41
{
strings:
	$a0 = { ee0515eaca490775b055315d780802d2b6d883b7a96d669f1f6af62fd8ae8f9a07a157f8febd026391292b4e09db7c7b211c47b72ae5aecfa967016cc40d14959c92474bc7c0b5ba66d48a390e4e8da2bfca836fb68c8adee7 }

condition:
	$a0
}

        
