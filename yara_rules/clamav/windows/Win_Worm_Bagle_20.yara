rule Win_Worm_Bagle_20
{
strings:
	$a0 = { dd227a04674dc3e0ac9aeffe1b98c3f8e466c1e8e45a07d7c1f4e44ac702fe1b3793e4ed6fe455c0fce46cc0fe10bf2ddc467fff4c79385bbf9e0f196bdf107014874d844c4b4a7304b24363fff9bc1001eb4a9e49e26f58fea178bb41bcc4fd04f0447e063c140f0c65fec0 }

condition:
	$a0
}

        
