rule Win_Downloader_Small_1250
{
strings:
	$a0 = { 61c3ad020ff12142050a10ff0489e20807ff137efc48e5449e41736a676ccd65d86f692460bf3041be20e820aab9f150a2f3a466038cd8a8046889ed4dc15c55e994a41546182d17a3d94011bba030fe056a822d166eac2c6de8501a2a7eac14fe59c71f803b09062cc23b5053a25bc3214003d82315510968192a210e25c66e501558832ac4107a09740ae81f27f7e9dc75b832df20 }

condition:
	$a0
}

        