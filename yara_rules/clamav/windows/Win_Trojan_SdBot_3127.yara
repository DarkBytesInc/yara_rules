rule Win_Trojan_SdBot_3127
{
strings:
	$a0 = { 58b014aec32d8ce1716b405638fb00fa49a2cf829ac430d9f67b065c6fc4622fdf0b776fc2c7261d306d0f207b0370bd854e45e7cfe1e39f6abf5ba7456be2a5990442a1dd7e99c0e03dfb3f56b0d7d21f82bf3f2ad2793b2fc9905a6e00fa1b497429c37ad0ab6692307c73f557aaf64ac51ce86b6596ede2f64d9b660cf17dd3fbc140294498237cbd57f26275e2aad84472e060e1 }

condition:
	$a0
}

        