rule Win_Downloader_Banload_838
{
strings:
	$a0 = { 6dbf771320a98781c2e592593f3fabbac0f9f4f6f10a2761c7837d93bf91431d4fd23ade18658fb89d82d7bebf4fc1412faf83266e9d76b84154a1599817560d023569748ade830b }

condition:
	$a0
}

        
