rule Win_Downloader_Banload_1808
{
strings:
	$a0 = { ee1671ee67965507df65a7adfe63dcee9aa6a98a178a05a63f669456eb0dc884dc5b5411af2a49f95a1f863a435e218126df8b700f64f9f689c229436afd0b53fd9ff815a65b77a32a7f7593bb20beba33ed864e656817802e9c3adae3ae5cdc684c3cf1 }

condition:
	$a0
}

        
