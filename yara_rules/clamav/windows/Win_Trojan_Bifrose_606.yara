rule Win_Trojan_Bifrose_606
{
strings:
	$a0 = { abc0c85537b6bfa8c43d3b83ab5cc8e47865d0788bcd758be444b7ce4843c0436beb446c6f13671a6e6c5b20bbaa5a27f694b704c787e2fe5eb9324b08974b4ecff3041518e53bd5c9db17d6b3c9c1b77f8eaf0f8a336bead265cbc919228192b7461540142fa22e037101235d757eeb6da949e8f0fb59164168ebf1d234ba0a9ebdc6a0119e937af8e4046a6c34edb62bbc63472544 }

condition:
	$a0
}

        