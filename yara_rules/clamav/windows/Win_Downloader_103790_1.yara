rule Win_Downloader_103790_1
{
strings:
	$a0 = { 558bec33c05568b9a8450064ff30648920ff05286d4600751eb8c0514600e8d59cfaffb8bc514600e8cb9cfaffb8b8514600e8c19cfaff33c05a595964891068c0a84500 }

condition:
	$a0
}

        