rule Win_Trojan_Vundo_156
{
strings:
	$a0 = { c64424a2f0895424c1d24424d1c78424d3ffffff6991f682c04424d2eed34c24e2896c24d10f1a8f3d92a3d3d34c24a2d34c24b4c78424b4ffffff1c1367d2d24424d1c18c24b6ffffff250f1dfac18424a2ffffffabc74424a30845606c899424b3ffffffc64424d6b4c64424d5dd895424e183ec04310424d28c24a0ffffffc04c24d152887424b0330424 }

condition:
	$a0
}

        