rule Win_Downloader_Dadobra_240
{
strings:
	$a0 = { 52a5db021a355c679326923aa0ce2f715abf000fa955e50a05fc959210fe196eea3c547d7cce3ed5f373bad163a47598b0d812d0d82a80fe09e43c942a51dc116501d6e6fc4eff868d0ad08cdb209ca1417eb75f1e }

condition:
	$a0
}

        
