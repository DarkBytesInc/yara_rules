rule Win_Worm_Kidala_6
{
strings:
	$a0 = { 6bd5690d2def20ecd41b720ce8f37a64341b1c1e510de8a6d4f5390cf82cc85e32663e5fdf59759ee7d7240e4f5008ccad5c67f089355728b7c3e7800d7dd53d63a31a4731f3892925be838b08f12410021380619b86af663d772842f4bf52c54b8a1b0afce9b88bd26601f62564b4ed15ca54 }

condition:
	$a0
}

        