rule Win_Worm_SpyBot_6
{
strings:
	$a0 = { b1c47bfea2850e6a55ec8a74e9c1e69be28d42a607140a43a0706d7d144536ae151ac6eca19856e50785190fe577b41d078ef75bae50bd07ef81f32da8013483eb373fbca3c49ada58970c47972b5355 }

condition:
	$a0
}

        
