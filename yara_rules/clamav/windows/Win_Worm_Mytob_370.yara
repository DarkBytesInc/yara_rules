rule Win_Worm_Mytob_370
{
strings:
	$a0 = { 5d30ca78febecc820a158ac182758cc25f487b82e1ed34be8522e701c8d008805255545a39c4267ed9cb80d3c9d1cc5d312ac05634420421ea1f3a24e23eee4c4d3269fd2df0667a547d8f2e1c646f76b169706b801a7a2b620eb40d80ff5270481c085c410916537c243e4038405544405f57405a690e51450d70900072524a038e58413e049174130eaa5fa8c8205364cc69d648eb }

condition:
	$a0
}

        