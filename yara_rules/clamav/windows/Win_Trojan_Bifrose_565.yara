rule Win_Trojan_Bifrose_565
{
strings:
	$a0 = { f01956b98ad5371e133acfb870e0d19c385ea8ce3487b9ab43befa9745c3b639b3660d823f8870a4befab1da229cefc43d963fddf6757e30b72f5eeaf1cd8567781f796413336d0b43e02d25f86942094faf0e6791b079656922472ef1285ec530cd21de9594f789b45e423b6c3e3a3f75b8c87b22b26edeaa17a9ec5c97080d3df91221f956169d27bc9b59fd6f80b61cc4839ebf3d }

condition:
	$a0
}

        