rule Win_Trojan_Spambot_247
{
strings:
	$a0 = { 09190e75ffffffff57ea6f52b0add94228616d3d59fc2e1e2321042f51ba6c06a851702c4f906c0fffbf7af4aaa80e52419d9b1bc685614ce88cd10b1d7608fbfffffffff5bd51a8c4829f9080412dbdaae4c7ab290742b71ee8b2c1857779b66bb4e619ffffffff54617daa4c52 }

condition:
	$a0
}

        
