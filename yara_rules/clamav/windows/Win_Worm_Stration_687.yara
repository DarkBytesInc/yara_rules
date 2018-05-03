rule Win_Worm_Stration_687
{
strings:
	$a0 = { 4d6f81a4bfa2b3d6ff3ffb90bfbab3d60f8ebfa8acb9a899a2a2a1a5a8a1bd2917662dfd9ea3acbdbe88b92df04567fe97ffff7a767066662627537c67666115005674697575353448637e7206ffddff5ff7cbd1c6c2c79091e5cad1d0d7a38faab0a7a3a6f1f08ca7f0c8bfe1bab6c2a25d7f6e57757e6f76 }

condition:
	$a0
}

        
