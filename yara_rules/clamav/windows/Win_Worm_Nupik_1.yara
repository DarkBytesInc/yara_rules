rule Win_Worm_Nupik_1
{
strings:
	$a0 = { e85f69feff0f85d20a0000b89cf24100e8abeaffffb8c4f24100e8a1eaffffb8f8f24100e897eaffffb81cf34100e88deaffffb840f34100e883eaffff }

condition:
	$a0
}

        
