rule Win_Trojan_Mybot_191
{
strings:
	$a0 = { fcfd25b16696e60767de9b8718949d80d81acdad263a2fc25f0481c82418eb3165f9021c272c9a1e206d33d47f59f429a770d93a237e2b2b1354fcdbe3bb3cbf79b926260e5b93e1deb63fd614c56c054569966f76ae90571baf34727934b43e2581c1d90f9782ea324b92b7cbd3ac7c06688aa13ab0e14b6b8c6b74343c850e756d28cd882aaa4fcbc9dcd768e3ddd01d66118eddfe }

condition:
	$a0
}

        