rule Win_Downloader_939_1
{
strings:
	$a0 = { f9c5c8fde75630b244b9e98bc4fa6e647ba8c348c419b4f2aa4185b1a0c2bdcd5b755841b1f6bcafb0de18d418f7ad0db6b5b6277aa0a4aeccf0be5029b31dd944bbf18009b5a21047b69b93e97716b1ce38030212634af6a155c091 }

condition:
	$a0
}

        
