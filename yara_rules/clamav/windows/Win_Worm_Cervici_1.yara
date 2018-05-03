rule Win_Worm_Cervici_1
{
strings:
	$a0 = { ff1a28fdf2ee20ed1fe2e8f0f3f1780ef9c05f4a6f6b65416941c3c0605854812c6daa6f83a7203d7148202d2077c1660a1bdc2c3d61c3007783a92f0da991f2b718bebd6e6f6fb65a617274e25d5d1c49be7a8b63bd6d7da8feb0ba7377e174 }

condition:
	$a0
}

        
